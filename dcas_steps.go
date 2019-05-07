/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddtests

import (
	"github.com/DATA-DOG/godog"
	"github.com/trustbloc/fabric-peer-test-lib/utils"
)

// DCASSteps ...
type DCASSteps struct {
	BDDContext *BDDContext
	content    string
	address    string
}

// NewDCASSteps ...
func NewDCASSteps(context *BDDContext) *DCASSteps {
	return &DCASSteps{BDDContext: context}
}

func (d *DCASSteps) setCASVariable(varName, value string) error {
	casKey := utils.GetCASKey([]byte(value))
	vars[varName] = casKey
	logger.Infof("Saving CAS key '%s' to variable '%s'", casKey, varName)
	return nil
}

func (d *DCASSteps) RegisterSteps(s *godog.Suite) {
	s.BeforeScenario(d.BDDContext.BeforeScenario)
	s.AfterScenario(d.BDDContext.AfterScenario)
	s.Step(`^variable "([^"]*)" is assigned the CAS key of value "([^"]*)"$`, d.setCASVariable)
}
