/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddtests

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveArg(t *testing.T) {
	vars := make(map[string]string)

	t.Run("Simple Variable", func(t *testing.T) {
		vars["var1"] = "val1"
		vars["var2"] = "val2"
		v, err := Resolve(vars, "${var1}")
		require.NoError(t, err)
		assert.Equal(t, "val1", v)

		v, err = Resolve(vars, "${var2}")
		require.NoError(t, err)
		assert.Equal(t, "val2", v)

		v, err = Resolve(vars, "${var3}")
		require.NoError(t, err)
		assert.Equal(t, "", v)

		v, err = Resolve(vars, "X_${var1}_${var2}")
		require.NoError(t, err)
		assert.Equal(t, "X_val1_val2", v)
	})

	t.Run("Array Variable", func(t *testing.T) {
		vars["arr"] = "v1,v12,v123"
		v, err := Resolve(vars, "${arr[0]}_${arr[1]}_${arr[2]}")
		require.NoError(t, err)
		assert.Equal(t, "v1_v12_v123", v)

		v, err = Resolve(vars, "${X[2]}")
		require.NoError(t, err)
		assert.Equal(t, "", v)
	})
}

func TestResolveArgInvalid(t *testing.T) {
	vars := make(map[string]string)

	t.Run("Simple Variable", func(t *testing.T) {
		vars["var1"] = "val1"
		_, err := Resolve(vars, "${var1")
		assert.EqualError(t, err, "expecting } for arg '${var1'")

		_, err = Resolve(vars, "$var2}")
		assert.NoError(t, err)
	})

	t.Run("Array Variable", func(t *testing.T) {
		vars["arr"] = "v1,v12,v123"
		_, err := Resolve(vars, "${arr[0}")
		assert.EqualError(t, err, "invalid arg '${arr[0}'")

		_, err = Resolve(vars, "${arr[1}")
		assert.EqualError(t, err, "invalid arg '${arr[1}'")

		_, err = Resolve(vars, "${arr[]}")
		assert.EqualError(t, err, "invalid index [] for arg '${arr[]}'")

		_, err = Resolve(vars, "${arr[999]}")
		assert.EqualError(t, err, "index [999] out of range for arg '${arr[999]}'")
	})
}

func TestResolveAll(t *testing.T) {
	vars := make(map[string]string)

	vars["var1"] = "val1"
	vars["var2"] = "val2"

	args, err := ResolveAll(vars, []string{"${var1}", "${var2}"})
	require.NoError(t, err)
	assert.Equal(t, []string{"val1", "val2"}, args)
}

func TestResolveVars(t *testing.T) {
	SetVar("v1", "value1")
	SetVar("v2", "value2")
	SetVar("v3", "value3")
	SetVar("v4", "value4")
	SetVar("v5", "value5")
	SetVar("v6", "value6")
	SetVar("v7", `{"key1":"value1"}`)
	SetVar("v8", `{"key2":"value2"}`)

	doc := make(map[string]interface{})
	err := json.Unmarshal([]byte(`{"v1":"${v1}","some-number":12345,"some-array":["${v2}","${v3}"],"some-doc":{"field1":"${v4}","field2":["${v5}","${v6}"]}}`), &doc)
	require.NoError(t, err)

	m, err := ResolveVars(doc)
	require.NoError(t, err)

	bytes, err := json.Marshal(m)
	require.NoError(t, err)
	require.Equal(t, `{"some-array":["value2","value3"],"some-doc":{"field1":"value4","field2":["value5","value6"]},"some-number":12345,"v1":"value1"}`, string(bytes))

	s, err := ResolveVars("[${v7},${v8}]")
	require.NoError(t, err)
	require.Equal(t, `[{"key1":"value1"},{"key2":"value2"}]`, s)
}

func TestResolveVarsInExpression(t *testing.T) {
	SetVar("v1", "value1")
	SetVar("v2", "value2")

	val1 := "v1 = ${v1}"
	val2 := "v2 = ${v2}"

	err := ResolveVarsInExpression(&val1, &val2)
	require.NoError(t, err)
	require.Equal(t, "v1 = value1", val1)
	require.Equal(t, "v2 = value2", val2)
}
