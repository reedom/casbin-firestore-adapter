package firestoreadapter

type Config struct {
	// Firestore collection name.
	// Optional. (Default: "casbin")
	Collection string
}

func (c Config) collectionName() string {
	if c.Collection != "" {
		return c.Collection
	}
	return defaultCollectionName
}
