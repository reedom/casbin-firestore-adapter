package firestoreadapter

import (
	"context"
	"runtime"

	"cloud.google.com/go/firestore"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"google.golang.org/api/iterator"
)

const defaultCollectionName = "casbin"

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	PType string `firestore:"p_type"`
	V0    string `firestore:"v0"`
	V1    string `firestore:"v1"`
	V2    string `firestore:"v2"`
	V3    string `firestore:"v3"`
	V4    string `firestore:"v4"`
	V5    string `firestore:"v5"`
}

// adapter represents the GCP firestore adapter for policy storage.
type adapter struct {
	client    *firestore.Client
	collection string
}

// finalizer is the destructor for adapter.
func finalizer(a *adapter) {
	a.close()
}

func (a *adapter) close() {
	_ = a.client.Close()
}

// NewAdapter is the constructor for Adapter. A valid firestore client must be provided.
func NewAdapter(db *firestore.Client) persist.Adapter {
	return NewAdapterWithConfig(db, Config{Collection: defaultCollectionName})
}

// NewAdapter is the constructor for Adapter. A valid firestore client must be provided.
func NewAdapterWithConfig(db *firestore.Client, config Config) persist.Adapter {
	a := &adapter{db, config.collectionName()}

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a
}

func (a *adapter) newQuery() firestore.Query {
	return a.client.Collection(a.collection).Where("p_type", ">", "")
}

func (a *adapter) LoadPolicy(model model.Model) error {
	var rules []CasbinRule

	ctx := context.Background()
	query := a.newQuery()
	iter := query.Documents(ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		var rule CasbinRule
		if err = doc.DataTo(&rule); err != nil {
			return err
		}
		rules = append(rules, rule)
	}
	for _, rule := range rules {
		loadPolicyLine(rule, model)
	}

	return nil
}

func (a *adapter) SavePolicy(model model.Model) error {
	var lines []interface{}

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}

	ctx := context.Background()
	policies := a.client.Collection(a.collection)
	err := a.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		iter := tx.Documents(a.newQuery())
		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return err
			}
			if err = tx.Delete(doc.Ref); err != nil {
				return err
			}
		}

		for _, line := range lines {
			if err := tx.Create(policies.NewDoc(), &line); err != nil {
				return err
			}
		}

		return nil
	})

	return err
}

func (a *adapter) AddPolicy(sec string, ptype string, rule []string) error {
	ctx := context.Background()
	line := savePolicyLine(ptype, rule)
	policies := a.client.Collection(a.collection)
	err := a.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		return tx.Create(policies.NewDoc(), &line)
	})
	return err
}

func (a *adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	ctx := context.Background()
	q := a.newQuery().
		Where("p_type", "==", line.PType).
		Where("v0", "==", line.V0).
		Where("v1", "==", line.V1).
		Where("v2", "==", line.V2).
		Where("v3", "==", line.V3).
		Where("v4", "==", line.V4)

	return a.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		iter := tx.Documents(q)
		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return err
			}
			if err = tx.Delete(doc.Ref); err != nil {
				return err
			}
		}
		return nil
	})
}

func (a *adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {

	ctx := context.Background()

	selector := make(map[string]interface{})
	selector["p_type"] = ptype

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		if fieldValues[0-fieldIndex] != "" {
			selector["v0"] = fieldValues[0-fieldIndex]
		}
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		if fieldValues[1-fieldIndex] != "" {
			selector["v1"] = fieldValues[1-fieldIndex]
		}
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		if fieldValues[2-fieldIndex] != "" {
			selector["v2"] = fieldValues[2-fieldIndex]
		}
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		if fieldValues[3-fieldIndex] != "" {
			selector["v3"] = fieldValues[3-fieldIndex]
		}
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		if fieldValues[4-fieldIndex] != "" {
			selector["v4"] = fieldValues[4-fieldIndex]
		}
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		if fieldValues[5-fieldIndex] != "" {
			selector["v5"] = fieldValues[5-fieldIndex]
		}
	}

	q := a.newQuery()
	for k, v := range selector {
		q = q.Where(k, "==", v)
	}

	return a.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		iter := tx.Documents(q)
		for {
			doc, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return err
			}
			if err = tx.Delete(doc.Ref); err != nil {
				return err
			}
		}
		return nil
	})
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{
		PType: ptype,
	}

	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

func loadPolicyLine(line CasbinRule, model model.Model) {
	key := line.PType
	sec := key[:1]

	tokens := []string{}
	if line.V0 != "" {
		tokens = append(tokens, line.V0)
	} else {
		goto LineEnd
	}

	if line.V1 != "" {
		tokens = append(tokens, line.V1)
	} else {
		goto LineEnd
	}

	if line.V2 != "" {
		tokens = append(tokens, line.V2)
	} else {
		goto LineEnd
	}

	if line.V3 != "" {
		tokens = append(tokens, line.V3)
	} else {
		goto LineEnd
	}

	if line.V4 != "" {
		tokens = append(tokens, line.V4)
	} else {
		goto LineEnd
	}

	if line.V5 != "" {
		tokens = append(tokens, line.V5)
	} else {
		goto LineEnd
	}

LineEnd:
	model[sec][key].Policy = append(model[sec][key].Policy, tokens)
}
