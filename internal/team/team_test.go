package team

import (
	"testing"

	"github.com/NazifSelimi/httpowl-api/internal/sites"
)

func TestCanGrant(t *testing.T) {
	if !canGrant(sites.RoleOwner, sites.RoleOwner) || !canGrant(sites.RoleAdmin, sites.RoleClient) {
		t.Fatal("expected grant")
	}
	if canGrant(sites.RoleAdmin, sites.RoleAdmin) || canGrant(sites.RoleAdmin, sites.RoleOwner) || canGrant(sites.RoleViewer, sites.RoleClient) {
		t.Fatal("privilege escalation allowed")
	}
}
