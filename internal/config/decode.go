package config

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

// decodeInto walks a parsed document and fills dst, which must be a pointer to
// a struct. Fields are matched by their `yaml` tag, falling back to a
// case-insensitive match on the field name.
func decodeInto(n node, dst any, path string) error {
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Pointer || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("decode target must be a non-nil struct pointer")
	}
	return decodeStruct(n, v.Elem(), path)
}

func decodeStruct(n node, v reflect.Value, path string) error {
	if n.kind != kindMap {
		return &httpx.ConfigError{Field: path, Value: n.String(), Err: fmt.Errorf("expected a mapping")}
	}
	fields := indexFields(v.Type())
	for _, key := range n.keys {
		field, ok := fields[strings.ToLower(key)]
		if !ok {
			return &httpx.ConfigError{Field: join(path, key), Value: n.maps[key].String(), Err: fmt.Errorf("unknown configuration key")}
		}
		if err := decodeValue(n.maps[key], v.Field(field), join(path, key)); err != nil {
			return err
		}
	}
	return nil
}

func indexFields(t reflect.Type) map[string]int {
	fields := make(map[string]int, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue // unexported
		}
		name := f.Tag.Get("yaml")
		if idx := strings.IndexByte(name, ','); idx >= 0 {
			name = name[:idx]
		}
		if name == "" {
			name = f.Name
		}
		fields[strings.ToLower(name)] = i
	}
	return fields
}

func decodeValue(n node, v reflect.Value, path string) error {
	switch v.Kind() {
	case reflect.String:
		if n.kind == kindSeq {
			return &httpx.ConfigError{Field: path, Value: n.String(), Err: fmt.Errorf("expected a scalar")}
		}
		v.SetString(n.scalar)
		return nil

	case reflect.Bool:
		b, err := strconv.ParseBool(strings.ToLower(n.scalar))
		if err != nil {
			return &httpx.ConfigError{Field: path, Value: n.scalar, Err: fmt.Errorf("expected true or false")}
		}
		v.SetBool(b)
		return nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, err := strconv.ParseInt(strings.TrimSpace(n.scalar), 10, 64)
		if err != nil {
			return &httpx.ConfigError{Field: path, Value: n.scalar, Err: fmt.Errorf("expected an integer")}
		}
		v.SetInt(i)
		return nil

	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(strings.TrimSpace(n.scalar), 64)
		if err != nil {
			return &httpx.ConfigError{Field: path, Value: n.scalar, Err: fmt.Errorf("expected a number")}
		}
		v.SetFloat(f)
		return nil

	case reflect.Struct:
		return decodeStruct(n, v, path)

	case reflect.Slice:
		return decodeSlice(n, v, path)

	case reflect.Map:
		return decodeMap(n, v, path)

	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		return decodeValue(n, v.Elem(), path)

	default:
		return &httpx.ConfigError{Field: path, Value: n.String(), Err: fmt.Errorf("unsupported field type %s", v.Kind())}
	}
}

func decodeSlice(n node, v reflect.Value, path string) error {
	elem := v.Type().Elem()
	switch n.kind {
	case kindSeq:
		out := reflect.MakeSlice(v.Type(), 0, len(n.seq))
		for i, item := range n.seq {
			slot := reflect.New(elem).Elem()
			if err := decodeValue(item, slot, path+"["+strconv.Itoa(i)+"]"); err != nil {
				return err
			}
			out = reflect.Append(out, slot)
		}
		v.Set(out)
		return nil

	case kindScalar:
		// A scalar targeting a slice of strings is either an inline list
		// (`[a, b]`) or a single element.
		if elem.Kind() != reflect.String {
			return &httpx.ConfigError{Field: path, Value: n.scalar, Err: fmt.Errorf("expected a sequence")}
		}
		if items, ok := parseInlineList(n.scalar); ok {
			out := reflect.MakeSlice(v.Type(), 0, len(items))
			for _, item := range items {
				out = reflect.Append(out, reflect.ValueOf(item).Convert(elem))
			}
			v.Set(out)
			return nil
		}
		out := reflect.MakeSlice(v.Type(), 0, 1)
		out = reflect.Append(out, reflect.ValueOf(n.scalar).Convert(elem))
		v.Set(out)
		return nil

	default:
		return &httpx.ConfigError{Field: path, Value: n.String(), Err: fmt.Errorf("expected a sequence")}
	}
}

func decodeMap(n node, v reflect.Value, path string) error {
	if n.kind != kindMap {
		return &httpx.ConfigError{Field: path, Value: n.String(), Err: fmt.Errorf("expected a mapping")}
	}
	keyType := v.Type().Key()
	valType := v.Type().Elem()
	out := reflect.MakeMapWithSize(v.Type(), len(n.keys))
	for _, key := range n.keys {
		slot := reflect.New(valType).Elem()
		if err := decodeValue(n.maps[key], slot, join(path, key)); err != nil {
			return err
		}
		out.SetMapIndex(reflect.ValueOf(key).Convert(keyType), slot)
	}
	v.Set(out)
	return nil
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
