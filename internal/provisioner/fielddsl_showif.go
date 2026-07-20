package provisioner

import "fmt"

// lintCondition checks one show_if value against the CLOSED grammar:
// map = AND; per operand a scalar (equals), a list (IN), or a one-key map of
// not|gt|gte|lt|lte; the reserved key `any` takes a list of maps (OR).
func lintCondition(where string, condition any, operands map[string]bool) []string {
	problems := []string{}
	block, ok := condition.(map[string]any)
	if !ok {
		return []string{where + ": must be a map (the closed grammar has no expression strings)"}
	}
	for key, value := range block {
		if key == "any" {
			branches := anyList(value)
			if len(branches) == 0 {
				problems = append(problems, where+".any: must be a list of condition maps")
				continue
			}
			for i, branch := range branches {
				problems = append(problems, lintCondition(fmt.Sprintf("%s.any[%d]", where, i), branch, operands)...)
			}
			continue
		}
		if !operands[key] {
			problems = append(problems, where+fmt.Sprintf(": operand %q is not an earlier-declared field or a role-enable flag (<metadata.roles[].name>_enabled)", key))
		}
		switch spec := value.(type) {
		case map[string]any:
			if len(spec) != 1 {
				problems = append(problems, where+"."+key+": operator maps take exactly one of not, gt, gte, lt, lte")
				continue
			}
			for op, operand := range spec {
				switch op {
				case "not":
				case "gt", "gte", "lt", "lte":
					if _, numeric := anyFloat(operand); !numeric {
						problems = append(problems, where+"."+key+"."+op+fmt.Sprintf(": needs a numeric operand (%v)", operand))
					}
				default:
					problems = append(problems, where+"."+key+fmt.Sprintf(": unknown operator %q — the closed set is not, gt, gte, lt, lte", op))
				}
			}
		default:
			// Scalar (equals) or list (IN) — both closed-legal as-is.
		}
	}
	return problems
}

// evalCondition evaluates a linted show_if against the value set (map = AND;
// any = OR). Unknown structure evaluates false — lint prevents it existing.
func evalCondition(condition any, values map[string]any) bool {
	block, ok := condition.(map[string]any)
	if !ok {
		return false
	}
	for key, spec := range block {
		if key == "any" {
			matched := false
			for _, branch := range anyList(spec) {
				if evalCondition(branch, values) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
			continue
		}
		if !matchOperand(values[key], spec) {
			return false
		}
	}
	return true
}

// matchOperand applies one operand's condition: scalar equals, list IN,
// operator map.
func matchOperand(value, spec any) bool {
	switch condition := spec.(type) {
	case []any:
		for _, candidate := range condition {
			if looseEqual(value, candidate) {
				return true
			}
		}
		return false
	case map[string]any:
		for op, operand := range condition {
			switch op {
			case "not":
				if list, isList := operand.([]any); isList {
					for _, candidate := range list {
						if looseEqual(value, candidate) {
							return false
						}
					}
					return true
				}
				return !looseEqual(value, operand)
			case "gt", "gte", "lt", "lte":
				left, lok := anyFloat(value)
				right, rok := anyFloat(operand)
				if !lok || !rok {
					return false
				}
				switch op {
				case "gt":
					return left > right
				case "gte":
					return left >= right
				case "lt":
					return left < right
				default:
					return left <= right
				}
			}
		}
		return false
	default:
		return looseEqual(value, spec)
	}
}

// looseEqual compares the way both evaluators must (the shared-vector
// contract): numbers numerically across int/float/json shapes, booleans as
// booleans, everything else by canonical string form (so "5" equals 5 and
// true equals "true" — the JS-side coercion zoneweaver's evaluator shows).
func looseEqual(a, b any) bool {
	if af, aok := anyFloat(a); aok {
		if bf, bok := anyFloat(b); bok {
			return af == bf
		}
	}
	return fmt.Sprint(a) == fmt.Sprint(b)
}
