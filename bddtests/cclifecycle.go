/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddtests

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	fabApi "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	lifecyclepkg "github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/lifecycle"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
)

func (d *CommonSteps) lifecycleInstallCCToAllPeers(ccLabel, ccPath string) error {
	return d.doLifecycleInstallCCToOrg(ccPath, ccLabel, "")
}

func (d *CommonSteps) doLifecycleInstallCCToOrg(ccPath, ccLabel, orgIDs string) error {
	if err := ResolveVarsInExpression(&ccPath, &ccLabel, &orgIDs); err != nil {
		return err
	}

	logger.Infof("Preparing to install chaincode from path [%s] with label [%s] to orgs [%s]", ccPath, ccLabel, orgIDs)

	var oIDs []string
	if orgIDs != "" {
		oIDs = strings.Split(orgIDs, ",")
	} else {
		oIDs = d.BDDContext.orgs
	}

	var packageID string

	for _, orgID := range oIDs {
		targets, err := d.getLocalTargets(orgID, "")
		if err != nil {
			return err
		}

		resMgmtClient := d.BDDContext.ResMgmtClient(orgID, ADMIN)

		pkgBytes, err := lifecyclepkg.NewCCPackage(&lifecyclepkg.Descriptor{
			Path:  ccPath,
			Type:  pb.ChaincodeSpec_GOLANG,
			Label: ccLabel,
		})
		if err != nil {
			return err
		}

		if len(targets) == 0 {
			return errors.Errorf("no targets for chaincode [%s]", ccLabel)
		}

		// Filter out the targets that already have the package installed
		var filteredTargets []string
		for _, target := range targets {
			if err := d.queryInstalledCCPackage(target, packageID); err != nil {
				filteredTargets = append(filteredTargets, target)
			}
		}

		if len(filteredTargets) == 0 {
			logger.Infof("... not installing chaincode [%s] to any peer in org [%s] since the package is already installed on all peers", ccLabel, orgID)

			continue
		}

		logger.Infof("... installing chaincode [%s] from path [%s] to targets %s", ccLabel, ccPath, filteredTargets)

		responses, err := resMgmtClient.LifecycleInstallCC(
			resmgmt.LifecycleInstallCCRequest{
				Label:   ccLabel,
				Package: pkgBytes,
			},
			resmgmt.WithRetry(resMgmtRetryOpts),
			resmgmt.WithTargetEndpoints(filteredTargets...),
		)
		if err != nil {
			return fmt.Errorf("SendInstallProposal return error: %s", err)
		}

		for _, r := range responses {
			if packageID != "" && packageID != r.PackageID {
				return errors.Errorf("PackageID [%s] does not match [%s]", r.PackageID, packageID)
			}

			packageID = r.PackageID
		}
	}

	logger.Infof("Setting response from install chaincode: %s", packageID)

	SetResponse(packageID)

	return nil
}

func (d *CommonSteps) queryInstalledCCPackage(peerID, packageID string) error {
	if err := ResolveVarsInExpression(&peerID, &packageID); err != nil {
		return err
	}

	logger.Infof("Preparing to query installed chaincode package [%s] on peer [%s]", packageID, peerID)

	if peerID == "" {
		return errors.Errorf("peer not provided")
	}

	peers, err := d.Peers(peerID)
	if err != nil {
		return err
	}

	peerConfig := peers[0]

	peer, err := d.BDDContext.OrgUserContext(peerConfig.OrgID, ADMIN).InfraProvider().CreatePeerFromConfig(&fabApi.NetworkPeer{PeerConfig: peerConfig.Config})
	if err != nil {
		return errors.WithMessage(err, "NewPeer failed")
	}

	resMgmtClient := d.BDDContext.ResMgmtClient(peerConfig.OrgID, ADMIN)

	logger.Infof("... querying installed chaincode package ID [%s]", packageID)

	resp, err := resMgmtClient.LifecycleGetInstalledCCPackage(
		packageID,
		resmgmt.WithTargets(peer),
		resmgmt.WithTimeout(fabApi.Execute, 30*time.Second),
		resmgmt.WithRetry(resMgmtRetryOpts),
	)
	if err != nil {
		return fmt.Errorf("GetInstalledCCPackage returned error: %s", err)
	}

	logger.Infof("Successfully got chaincode package of %d bytes", len(resp))

	return nil
}

func (d *CommonSteps) queryInstalledCC(peerID string) error {
	if err := ResolveVarsInExpression(&peerID); err != nil {
		return err
	}

	logger.Infof("Preparing to query installed chaincodes on peer [%s]", peerID)

	if peerID == "" {
		return errors.Errorf("peer not provided")
	}

	peers, err := d.Peers(peerID)
	if err != nil {
		return err
	}

	peerConfig := peers[0]

	peer, err := d.BDDContext.OrgUserContext(peerConfig.OrgID, ADMIN).InfraProvider().CreatePeerFromConfig(&fabApi.NetworkPeer{PeerConfig: peerConfig.Config})
	if err != nil {
		return errors.WithMessage(err, "NewPeer failed")
	}

	resMgmtClient := d.BDDContext.ResMgmtClient(peerConfig.OrgID, ADMIN)

	resp, err := resMgmtClient.LifecycleQueryInstalledCC(
		resmgmt.WithTargets(peer),
		resmgmt.WithTimeout(fabApi.Execute, 10*time.Second),
		resmgmt.WithRetry(resMgmtRetryOpts),
	)
	if err != nil {
		return fmt.Errorf("LifecycleQueryInstalledCC returned error: %s", err)
	}

	ccBytes, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	queryValue = string(ccBytes)

	logger.Infof("Installed chaincodes: %s", queryValue)

	return nil
}

func (d *CommonSteps) approveCCByOrg(ccID, ccVersion, packageID string, sequence int64, orgIDs, channelID string, ccPolicy, collectionNames string) error {
	return d.doApproveCCByOrg(ccID, ccVersion, packageID, sequence, orgIDs, channelID, ccPolicy, collectionNames, false)
}

func (d *CommonSteps) approveCCByOrgWithError(ccID, ccVersion, packageID string, sequence int64, orgIDs, channelID string, ccPolicy, collectionNames string, expectedError string) error {
	if err := ResolveVarsInExpression(&expectedError); err != nil {
		return err
	}

	err := d.doApproveCCByOrg(ccID, ccVersion, packageID, sequence, orgIDs, channelID, ccPolicy, collectionNames, false)
	if err == nil {
		return errors.Errorf("expecting error [%s] but got no error", expectedError)
	}

	if !strings.Contains(err.Error(), expectedError) {
		return errors.Errorf("expecting error [%s] but got [%s]", expectedError, err)
	}

	return nil
}

func (d *CommonSteps) doApproveCCByOrg(ccID, ccVersion, packageID string, sequence int64, orgIDs, channelID string, ccPolicy, collectionNames string, initRequired bool) error {
	if err := ResolveVarsInExpression(&ccID, &ccVersion, &packageID, &orgIDs, &channelID, &ccPolicy, &collectionNames); err != nil {
		return err
	}

	logger.Infof("Preparing to approve chaincode [%s] version [%s] with package ID [%s] on orgs [%s] on channel [%s] with CC policy [%s] and collectionPolicy [%s]", ccID, ccVersion, packageID, orgIDs, channelID, ccPolicy, collectionNames)

	sdkPeers, orgID, err := d.getOrgPeers(orgIDs, channelID)
	if err != nil {
		return err
	}

	chaincodePolicy, err := d.newChaincodePolicy(ccPolicy, channelID)
	if err != nil {
		return fmt.Errorf("error creating endorsement policy: %s", err)
	}

	collConfig, err := d.getCollectionConfig(channelID, ccID, collectionNames)
	if err != nil {
		return err
	}

	resMgmtClient := d.BDDContext.ResMgmtClient(orgID, ADMIN)

	// Check if the chaincode is already approved by this org
	peers := d.OrgPeers(orgIDs, channelID)
	if len(peers) == 0 {
		return errors.Errorf("no peers found for orgs [%s]", orgIDs)
	}

	if err := d.queryApprovedCCByPeer(peers[0].PeerID, ccID, sequence, channelID); err == nil {
		logger.Infof("... not approving chaincode [%s] since chaincode has already been approved by org [%s]", ccID, orgID)

		return nil
	}

	logger.Infof("... approving chaincode [%s]", ccID)

	_, err = resMgmtClient.LifecycleApproveCC(
		channelID,
		resmgmt.LifecycleApproveCCRequest{
			Name:             ccID,
			Version:          ccVersion,
			PackageID:        packageID,
			Sequence:         sequence,
			SignaturePolicy:  chaincodePolicy,
			CollectionConfig: collConfig,
			InitRequired:     initRequired,
		},
		resmgmt.WithTargets(sdkPeers...),
		resmgmt.WithTimeout(fabApi.Execute, 30*time.Second),
		resmgmt.WithRetry(resMgmtRetryOpts),
	)
	if err != nil {
		return fmt.Errorf("ApproveCC returned error: %s", err)
	}

	return nil
}

func (d *CommonSteps) queryApprovedCCByPeer(peerID, ccID string, sequence int64, channelID string) error {
	if err := ResolveVarsInExpression(&peerID, &ccID, &channelID); err != nil {
		return err
	}

	logger.Infof("Preparing to query approved chaincode definition of chaincode [%s] with sequence [%d] on peer [%s]", ccID, sequence, peerID)

	if peerID == "" {
		return errors.Errorf("peer not provided")
	}

	peers, err := d.Peers(peerID)
	if err != nil {
		return err
	}

	peerConfig := peers[0]

	peer, err := d.BDDContext.OrgUserContext(peerConfig.OrgID, ADMIN).InfraProvider().CreatePeerFromConfig(&fabApi.NetworkPeer{PeerConfig: peerConfig.Config})
	if err != nil {
		return errors.WithMessage(err, "NewPeer failed")
	}

	resMgmtClient := d.BDDContext.ResMgmtClient(peerConfig.OrgID, ADMIN)

	logger.Infof("... querying approved chaincode definition for [%s]", ccID)

	resp, err := resMgmtClient.LifecycleQueryApprovedCC(
		channelID,
		resmgmt.LifecycleQueryApprovedCCRequest{
			Name:     ccID,
			Sequence: sequence,
		},
		resmgmt.WithTargets(peer),
		resmgmt.WithTimeout(fabApi.Execute, 30*time.Second),
		resmgmt.WithRetry(resMgmtRetryOpts),
	)
	if err != nil {
		return fmt.Errorf("LifecycleQueryApprovedCC returned error: %s", err)
	}

	ccDefBytes, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	queryValue = string(ccDefBytes)

	logger.Infof("Chaincode definition: %s", queryValue)

	return nil
}

func (d *CommonSteps) checkCommitReadinessByOrg(ccID, ccVersion string, sequence int64, orgIDs, channelID string, ccPolicy, collectionNames string) error {
	return d.doCheckCommitReadinessByOrg(ccID, ccVersion, sequence, orgIDs, channelID, ccPolicy, collectionNames, false)
}

func (d *CommonSteps) doCheckCommitReadinessByOrg(ccID, ccVersion string, sequence int64, orgIDs, channelID string, ccPolicy, collectionNames string, initRequired bool) error {
	if err := ResolveVarsInExpression(&ccID, &ccVersion, &orgIDs, &channelID, &ccPolicy, &collectionNames); err != nil {
		return err
	}

	logger.Infof("Preparing to check commit readiness of chaincode [%s] version [%s] on orgs [%s] on channel [%s] with CC policy [%s] and collectionPolicy [%s]", ccID, orgIDs, channelID, ccPolicy, collectionNames)

	chaincodePolicy, err := d.newChaincodePolicy(ccPolicy, channelID)
	if err != nil {
		return fmt.Errorf("error creating endorsement policy: %s", err)
	}

	sdkPeers, orgID, err := d.getOrgPeers(orgIDs, channelID)
	if err != nil {
		return err
	}

	collConfig, err := d.getCollectionConfig(channelID, ccID, collectionNames)
	if err != nil {
		return err
	}

	resMgmtClient := d.BDDContext.ResMgmtClient(orgID, ADMIN)

	logger.Infof("... checking chaincode [%s] for commit readiness", ccID)

	resp, err := resMgmtClient.LifecycleCheckCCCommitReadiness(
		channelID,
		resmgmt.LifecycleCheckCCCommitReadinessRequest{
			Name:             ccID,
			Version:          ccVersion,
			Sequence:         sequence,
			SignaturePolicy:  chaincodePolicy,
			CollectionConfig: collConfig,
			InitRequired:     initRequired,
		},
		resmgmt.WithTargets(sdkPeers...),
		resmgmt.WithTimeout(fabApi.Execute, 30*time.Second),
		resmgmt.WithRetry(resMgmtRetryOpts),
	)
	if err != nil {
		return fmt.Errorf("CheckCCCommitReadiness returned error: %s", err)
	}

	approvalBytes, err := json.Marshal(resp.Approvals)
	if err != nil {
		return err
	}

	queryValue = string(approvalBytes)

	logger.Infof("Approvals: %s", queryValue)

	return nil
}

func (d *CommonSteps) commitCCByOrg(ccID, ccVersion string, sequence int64, orgIDs, channelID string, ccPolicy, collectionNames string) error {
	return d.doCommitCCByOrg(ccID, ccVersion, sequence, orgIDs, channelID, ccPolicy, collectionNames, false)
}

func (d *CommonSteps) doCommitCCByOrg(ccID, ccVersion string, sequence int64, orgIDs, channelID string, ccPolicy, collectionNames string, initRequired bool) error {
	if err := ResolveVarsInExpression(&ccID, &ccVersion, &orgIDs, &channelID, &ccPolicy, &collectionNames); err != nil {
		return err
	}

	if err := d.queryCommittedCCByOrg(ccID, orgIDs, channelID); err == nil {
		for _, a := range gjson.Get(queryValue, "#.Version").Array() {
			if a.Str == ccVersion {
				logger.Infof("... not committing chaincode [%s:%s] since chaincode has already been committed", ccID, ccVersion)
				return nil
			}
		}
	} else {
		logger.Infof("Got error querying for committed chaincode [%s]: %s", ccID, err)
	}

	logger.Infof("Preparing to commit chaincode [%s] version [%s] sequence [%d] on orgs [%s] on channel [%s] with CC policy [%s] and collectionPolicy [%s]", ccID, ccVersion, sequence, orgIDs, channelID, ccPolicy, collectionNames)

	sdkPeers, orgID, err := d.getOrgPeers(orgIDs, channelID)
	if err != nil {
		return err
	}

	chaincodePolicy, err := d.newChaincodePolicy(ccPolicy, channelID)
	if err != nil {
		return fmt.Errorf("error creating endorsement policy: %s", err)
	}

	collConfig, err := d.getCollectionConfig(channelID, ccID, collectionNames)
	if err != nil {
		return err
	}

	resMgmtClient := d.BDDContext.ResMgmtClient(orgID, ADMIN)

	logger.Infof("... committing chaincode [%s]", ccID)

	_, err = resMgmtClient.LifecycleCommitCC(
		channelID,
		resmgmt.LifecycleCommitCCRequest{
			Name:             ccID,
			Version:          ccVersion,
			Sequence:         sequence,
			SignaturePolicy:  chaincodePolicy,
			CollectionConfig: collConfig,
			InitRequired:     initRequired,
		},
		resmgmt.WithTargets(sdkPeers...),
		resmgmt.WithTimeout(fabApi.Execute, 30*time.Second),
		resmgmt.WithRetry(resMgmtRetryOpts),
	)
	if err != nil {
		return fmt.Errorf("CommitCC returned error: %s", err)
	}

	return nil
}

func (d *CommonSteps) queryCommittedCCByOrg(ccID, orgIDs, channelID string) error {
	return d.doQueryCommittedCCByOrg(ccID, orgIDs, channelID)
}

func (d *CommonSteps) queryCommittedCCsByOrg(orgIDs, channelID string) error {
	return d.doQueryCommittedCCByOrg("", orgIDs, channelID)
}

func (d *CommonSteps) doQueryCommittedCCByOrg(ccID, orgIDs, channelID string) error {
	if err := ResolveVarsInExpression(&ccID, &orgIDs, &channelID); err != nil {
		return err
	}

	logger.Infof("Preparing to query committed chaincode [%s] on orgs [%s] on channel [%s]", ccID, orgIDs, channelID)

	sdkPeers, orgID, err := d.getOrgPeers(orgIDs, channelID)
	if err != nil {
		return err
	}

	resMgmtClient := d.BDDContext.ResMgmtClient(orgID, ADMIN)

	logger.Infof("... querying chaincode definitions for [%s]", ccID)

	resp, err := resMgmtClient.LifecycleQueryCommittedCC(
		channelID,
		resmgmt.LifecycleQueryCommittedCCRequest{
			Name: ccID,
		},
		resmgmt.WithTargets(sdkPeers...),
		resmgmt.WithTimeout(fabApi.Execute, 30*time.Second),
		resmgmt.WithRetry(resMgmtRetryOpts),
	)
	if err != nil {
		return fmt.Errorf("QueryCCDefinitions returned error: %s", err)
	}

	ccDefBytes, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	queryValue = string(ccDefBytes)

	logger.Infof("Chaincode definitions: %s", queryValue)

	return nil
}

func (d *CommonSteps) approveAndCommitCCByOrg(ccID, ccVersion, packageID string, sequence int64, orgIDs, channelID string, ccPolicy, collectionNames string) error {
	return d.doApproveAndCommitCCByOrg(ccID, ccVersion, packageID, sequence, orgIDs, channelID, ccPolicy, collectionNames, false)
}

func (d *CommonSteps) doApproveAndCommitCCByOrg(ccID, ccVersion, packageID string, sequence int64, orgIDs, channelID string, ccPolicy, collectionNames string, initRequired bool) error {
	for _, orgID := range strings.Split(orgIDs, ",") {
		if err := d.doApproveCCByOrg(ccID, ccVersion, packageID, sequence, orgID, channelID, ccPolicy, collectionNames, false); err != nil {
			return err
		}
	}

	var err error
	for i := 0; i < 5; i++ {
		err = d.doCommitCCByOrg(ccID, ccVersion, sequence, orgIDs, channelID, ccPolicy, collectionNames, initRequired)
		if err == nil {
			logger.Infof("Successfully committed")

			return nil
		}

		logger.Infof("Not ready to commit: %s", err)

		time.Sleep(time.Second)

		continue
	}

	return err
}
