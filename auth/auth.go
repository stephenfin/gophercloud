package auth

type AuthV2Mechanism interface {
	ToAuthBody() ([]string, map[string]map[string]any, error)
	CanReauth() bool
}

type AuthV3Mechanism interface {
	ToAuthBody() ([]string, map[string]map[string]any, error)
	ToAuthHeaders() (map[string]any, error)
	CanReauth() bool
}

type AuthOptionsBuilder interface {
	Authenticate() error
}

type AuthOptionsV2 struct {
	AuthURL string
	Auth    AuthV2Mechanism
}

func (ao AuthOptionsV2) Authenticate() error {
	return nil
}

type AuthOptionsV3 struct {
	AuthURL     string
	AuthType    string
	AuthMethods []string
	Auth        AuthV3Mechanism
}

func (ao AuthOptionsV3) Authenticate() error {
	return nil
}
