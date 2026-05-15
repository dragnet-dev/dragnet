package stix

import "github.com/google/uuid"

// StixID generates a deterministic STIX ID from an object type and seed string.
// Running it with the same inputs always produces the same ID, so downstream
// tools (MISP, OpenCTI) won't create duplicate objects on re-import.
func StixID(objectType, seed string) string {
	u := uuid.NewSHA1(uuid.NameSpaceURL, []byte("dragnet:stix:"+objectType+":"+seed))
	return objectType + "--" + u.String()
}
