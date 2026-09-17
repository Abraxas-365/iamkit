package appsvc

import (
	"context"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/application"
)

type repositoryStub struct {
	updates int
	input   application.Update
}

func (*repositoryStub) Create(context.Context, string, string, application.Create) error { return nil }
func (*repositoryStub) Find(context.Context, string, string) (application.Application, error) {
	return application.Application{}, nil
}
func (*repositoryStub) List(context.Context, string) ([]application.Application, error) {
	return nil, nil
}
func (r *repositoryStub) Update(_ context.Context, _ application.Mutation, _ string, input application.Update) error {
	r.updates++
	r.input = input
	return nil
}
func TestPartialApplicationUpdate(t *testing.T) {
	r := &repositoryStub{}
	service := New(r)
	active := false
	if err := service.Update(context.Background(), application.Mutation{}, "4e9cfde9-b26b-4fb4-9c44-f6176255aa5d", application.Update{Active: &active}); err != nil {
		t.Fatal(err)
	}
	if r.updates != 1 || r.input.Name != nil || r.input.Redirects != nil || r.input.Active == nil || *r.input.Active {
		t.Fatal("partial update lost omitted fields")
	}
	blank := "  "
	if err := service.Update(context.Background(), application.Mutation{}, "4e9cfde9-b26b-4fb4-9c44-f6176255aa5d", application.Update{Name: &blank}); err == nil {
		t.Fatal("blank name accepted")
	}
	if r.updates != 1 {
		t.Fatal("invalid update reached repository")
	}
	redirects := []string{}
	if err := service.Update(context.Background(), application.Mutation{}, "4e9cfde9-b26b-4fb4-9c44-f6176255aa5d", application.Update{Redirects: &redirects}); err != nil {
		t.Fatal(err)
	}
	if r.input.Redirects == nil || len(*r.input.Redirects) != 0 {
		t.Fatal("explicit empty redirects lost")
	}
}
