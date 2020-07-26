package firestoreadapter

import (
	"context"
	"io/ioutil"

	"cloud.google.com/go/firestore"
	"github.com/casbin/casbin/v2/model"
)

type CasbinModelConf struct {
	Text string `firestore:"text"`
}

// SaveModel loads a casbin model definition from the specified file and store it to Firestore.
func SaveModel(db *firestore.Client, path string) error {
	return SaveModelWithConfig(db, path, Config{Collection:defaultCollectionName})
}

// SaveModel loads a casbin model definition from the specified file and store it to Firestore.
func SaveModelWithConfig(client *firestore.Client, path string, config Config) error {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(b)

	// Validate the specified config.
	if _, err = model.NewModelFromString(text); err != nil {
		return err
	}

	ctx := context.Background()
	err = client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		ref := client.Collection(config.collectionName()).Doc("conf")
		m := CasbinModelConf{text}
		return tx.Set(ref, &m)
	})
	return err
}

// LoadModel loads a casbin model definition from Firestore.
func LoadModel(client *firestore.Client) (model.Model, error) {
	return LoadModelWithConfig(client, Config{Collection:defaultCollectionName})
}

// LoadModel loads a casbin model definition from Firestore.
func LoadModelWithConfig(client *firestore.Client, config Config) (model.Model, error) {
	ctx := context.Background()
	ref := client.Collection(config.collectionName()).Doc("conf")
	docsnap, err := ref.Get(ctx)
	if err != nil {
		return nil, err
	}
	var conf CasbinModelConf
	if err = docsnap.DataTo(&conf); err != nil {
		return nil, err
	}

	return model.NewModelFromString(conf.Text)
}
