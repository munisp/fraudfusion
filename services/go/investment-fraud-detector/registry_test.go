package main

import (
	"strings"
	"testing"
)

func TestLoadSECRegistryCSV(t *testing.T) {
	csvData := "name,promoter_id,registration_number,entity_type\n" +
		"Stanbic IBTC Asset Management Limited,PROM-STANBIC-AM,SEC/CMO/AM-001,fund_manager\n" +
		"ARM Investment Managers Limited,PROM-ARM-IM,SEC/CMO/AM-002,fund_manager\n"
	entries, err := loadSECRegistryCSV(strings.NewReader(csvData))
	if err != nil || len(entries) != 2 {
		t.Fatalf("load = %d entries, err=%v", len(entries), err)
	}
	entry, ok := entries["stanbic ibtc asset management limited"]
	if !ok || entry.PromoterID != "PROM-STANBIC-AM" || entry.EntityType != "fund_manager" {
		t.Fatalf("entry = %+v ok=%t", entry, ok)
	}
}

func TestLoadSECRegistryCSVFailClosed(t *testing.T) {
	for _, bad := range []string{
		"",
		"promoter_id,entity_type\nPROM-1,fund_manager\n",     // no name column
		"name\n\n",                                           // empty name row
		"name,promoter_id\nOnly,Header\nbroken\n",            // short row (empty name at idx? no: short record)
	} {
		if _, err := loadSECRegistryCSV(strings.NewReader(bad)); err == nil {
			t.Fatalf("malformed CSV must be rejected: %q", bad)
		}
	}
	// Header only, zero rows.
	if _, err := loadSECRegistryCSV(strings.NewReader("name\n")); err == nil {
		t.Fatal("CSV with no licensee rows must be rejected")
	}
}

func TestRegistrySourceLabeling(t *testing.T) {
	secFileRegistry.Store(&map[string]secRegistryEntry{"x": {Name: "X"}})
	if registrySource() != "file" {
		t.Fatal("loaded file registry must report registry_source=file")
	}
	secFileRegistry.Store(nil)
	if registrySource() != "seed" {
		t.Fatal("no file registry must report registry_source=seed")
	}
}

func TestCheckSECRegistrationFromFileRegistry(t *testing.T) {
	secFileRegistry.Store(&map[string]secRegistryEntry{
		"stanbic ibtc asset management limited": {Name: "Stanbic IBTC Asset Management Limited", PromoterID: "PROM-STANBIC-AM"},
	})
	defer secFileRegistry.Store(nil)
	ok, err := checkSECRegistration("Stanbic IBTC Asset Management Limited", "")
	if err != nil || !ok {
		t.Fatalf("file registry hit = %t, %v", ok, err)
	}
	ok, err = checkSECRegistration("", "PROM-STANBIC-AM")
	if err != nil || !ok {
		t.Fatalf("promoter id hit = %t, %v", ok, err)
	}
	ok, err = checkSECRegistration("MMM Global", "")
	if err != nil || ok {
		t.Fatalf("unknown entity must be not-registered (not error), got %t, %v", ok, err)
	}
}
