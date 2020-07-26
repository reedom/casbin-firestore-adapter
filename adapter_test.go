package firestoreadapter

import (
	"context"
	"sort"
	"strings"
	"testing"

	"cloud.google.com/go/firestore"
	"github.com/casbin/casbin/v2"
)

func getClient() *firestore.Client {
	ctx := context.Background()
	ds, err := firestore.NewClient(ctx, "firestoreadapter")
	if err != nil {
		panic(err)
	}
	return ds
}

func testGetPolicy(e *casbin.Enforcer, wants [][]string, onFail func(actual, wants [][]string)) {
	actual := e.GetPolicy()
	if !SamePolicy(actual, wants) {
		sortPolicy(actual)
		sortPolicy(wants)
		onFail(actual, wants)
	}
}

func sortPolicy(policy [][]string) {
	sort.Slice(policy, func(i, j int) bool {
		n := strings.Compare(policy[i][0], policy[j][0])
		if n != 0 {
			n = strings.Compare(policy[i][1], policy[j][1])
			if n != 0 {
				n = strings.Compare(policy[i][2], policy[j][2])
			}
		}
		return n < 0
	})
}

func SamePolicy(a, b [][]string) bool {
	diff := make(map[string]bool, len(a))
	for _, v := range a {
		key := strings.Join(v, ",")
		diff[key] = false
	}
	for _, v := range b {
		key := strings.Join(v, ",")
		if _, ok := diff[key]; !ok {
			return false
		}
		diff[key] = true
	}
	for _, v := range diff {
		if !v {
			return false
		}
	}
	return true
}

func initPolicy(t *testing.T, config Config) {
	// Because the DB is empty at first,
	// so we need to load the policy from the file adapter (.CSV) first.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	a := NewAdapterWithConfig(getClient(), config)
	// This is a trick to save the current policy to the DB.
	// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	err := a.SavePolicy(e.GetModel())
	if err != nil {
		panic(err)
	}

	// Clear the current policy.
	e.ClearPolicy()
	testGetPolicy(e, [][]string{}, func(actual, wants [][]string) {
		t.Error("got: ", actual, ", wants ", wants)
	})

	// Load the policy from DB.
	err = a.LoadPolicy(e.GetModel())
	if err != nil {
		panic(err)
	}
	testGetPolicy(e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}}, func(actual, wants [][]string) {
		t.Error("got: ", actual, ", wants ", wants)
	})
}

func TestAdapter(t *testing.T) {
	config := Config{Collection: "firestoreadapter-unittest"}
	initPolicy(t, config)

	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a := NewAdapterWithConfig(getClient(), config)
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
	testGetPolicy(e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}}, func(actual, wants [][]string) {
		t.Error("got: ", actual, ", wants ", wants)
	})

	// AutoSave is enabled by default.
	// Now we disable it.
	e.EnableAutoSave(false)

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	// This is still the original policy.
	testGetPolicy(e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}}, func(actual, wants [][]string) {
		t.Error("got: ", actual, ", wants ", wants)
	})

	// Now we enable the AutoSave.
	e.EnableAutoSave(true)
	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}}, func(actual, wants [][]string) {
		t.Error("got: ", actual, ", wants ", wants)
	})

	// Remove the added rule.
	e.RemovePolicy("alice", "data1", "write")
	if err := a.RemovePolicy("p", "p", []string{"alice", "data1", "write"}); err != nil {
		t.Errorf("Expected RemovePolicy() to be successful; got %v", err)
	}
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}}, func(actual, wants [][]string) {
		t.Error("got: ", actual, ", wants ", wants)
	})

	// Remove "data2_admin" related policy rules via a filter.
	// Two rules: {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"} are deleted.
	e.RemoveFilteredPolicy(0, "data2_admin")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}}, func(actual, wants [][]string) {
		t.Error("got: ", actual, ", wants ", wants)
	})

	e.RemoveFilteredPolicy(1, "data1")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(e, [][]string{{"bob", "data2", "write"}}, func(actual, wants [][]string) {
		t.Error("got: ", actual, ", wants ", wants)
	})

	e.RemoveFilteredPolicy(2, "write")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(e, [][]string{}, func(actual, wants [][]string) {
		t.Error("got: ", actual, ", wants ", wants)
	})
}

func TestDeleteFilteredAdapter(t *testing.T) {
	a := NewAdapter(getClient())
	e, _ := casbin.NewEnforcer("examples/rbac_tenant_service.conf", a)

	e.AddPolicy("domain1", "alice", "data3", "read", "accept", "service1")
	e.AddPolicy("domain1", "alice", "data3", "write", "accept", "service2")

	// Reload the policy from the storage to see the effect.
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(e, [][]string{{"domain1", "alice", "data3", "read", "accept", "service1"},
		{"domain1", "alice", "data3", "write", "accept", "service2"}}, func(actual, wants [][]string) {
		t.Error("got: ", actual, ", wants ", wants)
	})
	// test RemoveFiltered Policy with "" fileds
	e.RemoveFilteredPolicy(0, "domain1", "", "", "read")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(e, [][]string{{"domain1", "alice", "data3", "write", "accept", "service2"}}, func(actual, wants [][]string) {
		t.Error("got: ", actual, ", wants ", wants)
	})

	e.RemoveFilteredPolicy(0, "domain1", "", "", "", "", "service2")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(e, [][]string{}, func(actual, wants [][]string) {
		t.Error("got: ", actual, ", wants ", wants)
	})
}
