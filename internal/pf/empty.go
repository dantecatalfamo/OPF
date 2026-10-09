package pf

import "reflect"

// EmptyModel is the model of a machine OPF has no configuration for:
// nothing configured, with every list and map empty rather than null,
// so what reads it (the web UI) sees the shape a real model has.
// Optional sections (pointers) stay absent.
func EmptyModel() *Model {
	m := &Model{}
	fillEmpty(reflect.ValueOf(m).Elem())
	return m
}

func fillEmpty(v reflect.Value) {
	switch v.Kind() {
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				fillEmpty(v.Field(i))
			}
		}
	case reflect.Slice:
		if v.IsNil() {
			v.Set(reflect.MakeSlice(v.Type(), 0, 0))
		}
	case reflect.Map:
		if v.IsNil() {
			v.Set(reflect.MakeMap(v.Type()))
		}
	}
}
