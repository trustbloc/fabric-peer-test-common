/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"strconv"
	"strings"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
	"github.com/pkg/errors"
)

var logger = logging.NewLogger("test-logger")

// Resolve resolves all variables within the given arg
//
// Example 1: Simple variable
// 	Given:
// 		vars = {
// 			"var1": "value1",
// 			"var2": "value2",
// 			}
//	Then:
//		"${var1}" = "value1"
//		"X_${var1}_${var2} = "X_value1_value2
//
// Example 2: Array variable
// 	Given:
// 		vars = {
// 			"arr1": "value1,value2,value3",
// 			}
//	Then:
//		"${arr1[0]_arr1[1]_arr1[2]}" = "value1_value2_value3"
//
func Resolve(vars map[string]string, arg string) (string, error) {
	for {
		str, err := doResolve(vars, arg)
		if err != nil {
			return arg, err
		}
		if str == arg {
			// Done
			return str, nil
		}
		arg = str
	}
}

func ResolveAll(vars map[string]string, args []string) ([]string, error) {
	argArr := make([]string, len(args))
	for i, arg := range args {
		v, err := Resolve(vars, arg)
		if err != nil {
			return nil, err
		}
		argArr[i] = v
	}
	return argArr, nil
}

func doResolve(vars map[string]string, arg string) (string, error) {
	if len(arg) <= 3 {
		return arg, nil
	}

	open := strings.Index(arg, "${")
	if open == -1 {
		return arg, nil
	}

	close := strings.Index(arg, "}")
	if close == -1 {
		return arg, errors.Errorf("expecting } for arg '%s'", arg)
	}

	// Check for array
	varName := arg[open+2 : close]
	ob := strings.Index(varName, "[")
	if ob == -1 {
		// Not an array
		return replace(arg, vars[varName], open, close), nil
	}

	cb := strings.Index(varName, "]")
	if cb == -1 {
		return arg, errors.Errorf("invalid arg '%s'", arg)
	}

	arrVar := varName[0:ob]
	values := vars[arrVar]

	if values == "" {
		return replace(arg, "", open, close), nil
	}

	index := varName[ob+1 : cb]

	vals := strings.Split(values, ",")
	i, err := strconv.Atoi(index)
	if err != nil {
		return arg, errors.Errorf("invalid index [%s] for arg '%s'", index, arg)
	}

	if i >= len(vals) {
		return arg, errors.Errorf("index [%d] out of range for arg '%s'", i, arg)
	}

	return replace(arg, vals[i], open, close), nil
}

func asTuples(args []string) ([]*tuple, error) {
	if len(args) == 0 {
		return nil, nil
	}

	if len(args)%2 != 0 {
		return nil, errors.New("missing value for key")
	}

	var tuples []*tuple
	for i := 0; i < len(args); i = i + 2 {
		tuples = append(tuples, &tuple{v1: args[i], v2: args[i+1]})
	}
	return tuples, nil
}

type tuple struct {
	v1 string
	v2 string
}

func replace(arg, value string, open, close int) string {
	return arg[0:open] + value + arg[close+1:]
}
