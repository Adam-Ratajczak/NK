package main

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}

	s := "?"
	for i := 1; i < n; i++ {
		s += ",?"
	}
	return s
}

func toInterfaceSlice[T any](arr []T) []interface{} {
	out := make([]interface{}, len(arr))
	for i, v := range arr {
		out[i] = v
	}
	return out
}
