package postgres

import (
	"reflect"
	"testing"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
)

// Every Options field is set from a non-zero config default (a field added
// to Options but not mapped fails here).
func TestOptionsFromConfigMapsEveryField(t *testing.T) {
	c := config.Defaults().Postgres
	c.BinaryPaths = []string{"/x"}
	c.EnableDelayAcct = true
	o := OptionsFromConfig(&c, true)
	v := reflect.ValueOf(o)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Errorf("Options.%s is not mapped", v.Type().Field(i).Name)
		}
	}
}
