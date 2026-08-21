package fluvio

import "context"

type Client struct { endpoint string }
type Event struct { ID string; Type string; Data map[string]interface{} }

func NewClient(endpoint string) (*Client, error) {
return &Client{endpoint}, nil
}

func (c *Client) ProduceEvent(ctx context.Context, userID string, event Event) error {
return nil
}

func (c *Client) Close() error { return nil }
