/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddtests

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/DATA-DOG/godog"
)

// SidetreeSteps ...
type SidetreeSteps struct {
	BDDContext *BDDContext
	content    string
	address    string
}

// NewSidetreeSteps ...
func NewSidetreeSteps(context *BDDContext) *SidetreeSteps {
	return &SidetreeSteps{BDDContext: context}
}

func (t *SidetreeSteps) writeContent(content, ccID, orgIDs, channelID string) error {

	commonSteps := NewCommonSteps(t.BDDContext)

	args := []string{"writeContent", content}
	resp, err := commonSteps.InvokeCCWithArgs(ccID, channelID, commonSteps.OrgPeers(orgIDs, channelID), args, nil)
	if err != nil {
		return fmt.Errorf("InvokeCCWithArgs return error: %s", err)
	}

	t.content = content
	t.address = string(resp.Payload)

	return nil
}

func (t *SidetreeSteps) readContent(ccID, orgIDs, channelID string) error {

	commonSteps := NewCommonSteps(t.BDDContext)

	args := []string{"readContent", t.address}
	payload, err := commonSteps.QueryCCWithArgs(false, ccID, channelID, args, nil, commonSteps.OrgPeers(orgIDs, channelID)...)
	if err != nil {
		return fmt.Errorf("QueryCCWithArgs return error: %s", err)
	}

	if payload != t.content {
		return fmt.Errorf("original content[%s] doesn't match retrieved content[%s]", t.content, payload)
	}

	return nil
}

func (t *SidetreeSteps) writeDocument(op *Operation, ccID, orgIDs, channelID string) error {

	commonSteps := NewCommonSteps(t.BDDContext)

	args := []string{"write", getJSON(op)}
	_, err := commonSteps.InvokeCCWithArgs(ccID, channelID, commonSteps.OrgPeers(orgIDs, channelID), args, nil)
	if err != nil {
		return fmt.Errorf("InvokeCCWithArgs return error: %s", err)
	}

	return nil
}

func (t *SidetreeSteps) createDocument(docID, ccID, orgIDs, channelID string) error {
	return t.writeDocument(getCreateOperation(docID), ccID, orgIDs, channelID)
}

func (t *SidetreeSteps) updateDocument(docID, ccID, orgIDs, channelID string) error {
	return t.writeDocument(getUpdateOperation(docID), ccID, orgIDs, channelID)
}

func (t *SidetreeSteps) queryDocumentByIndex(docID, ccID, numOfDocs, orgIDs, channelID string) error {

	commonSteps := NewCommonSteps(t.BDDContext)

	attrBytes, _ := json.Marshal([]string{docID})

	args := []string{"getByIndex", "did", string(attrBytes)}
	payload, err := commonSteps.QueryCCWithArgs(false, ccID, channelID, args, nil, commonSteps.OrgPeers(orgIDs, channelID)...)
	if err != nil {
		return fmt.Errorf("QueryCCWithArgs return error: %s", err)
	}

	var operations [][]byte
	err = json.Unmarshal([]byte(payload), &operations)
	if err != nil {
		return fmt.Errorf("failed to unmarshal operations: %s", err)
	}

	docsNum, err := strconv.Atoi(numOfDocs)
	if err != nil {
		return err
	}

	if len(operations) != docsNum {
		return fmt.Errorf("expecting %d, got %d", docsNum, len(operations))
	}

	return nil
}

func getJSON(op *Operation) string {

	bytes, err := json.Marshal(op)
	if err != nil {
		panic(err)
	}

	return string(bytes)
}

func getCreateOperation(did string) *Operation {
	return &Operation{DID: did, Operation: "create"}
}

func getUpdateOperation(did string) *Operation {
	return &Operation{DID: did, Operation: "update"}
}

type Operation struct {
	DID       string `json:"did,omitempty"`
	Operation string `json:"operation,omitempty"`
	Payload   string `json:"payload,omitempty"`
}

func (t *SidetreeSteps) RegisterSteps(s *godog.Suite) {
	s.BeforeScenario(t.BDDContext.BeforeScenario)
	s.AfterScenario(t.BDDContext.AfterScenario)
	s.Step(`^client writes content "([^"]*)" using "([^"]*)" on all peers in the "([^"]*)" org on the "([^"]*)" channel$`, t.writeContent)
	s.Step(`^client verifies that written content at the returned address from "([^"]*)" matches original content on all peers in the "([^"]*)" org on the "([^"]*)" channel$`, t.readContent)
	s.Step(`^client creates document with ID "([^"]*)" using "([^"]*)" on all peers in the "([^"]*)" org on the "([^"]*)" channel$`, t.createDocument)
	s.Step(`^client updates document with ID "([^"]*)" using "([^"]*)" on all peers in the "([^"]*)" org on the "([^"]*)" channel$`, t.updateDocument)
	s.Step(`^client verifies that query by index ID "([^"]*)" from "([^"]*)" will return "([^"]*)" versions of the document on all peers in the "([^"]*)" org on the "([^"]*)" channel$`, t.queryDocumentByIndex)
}
