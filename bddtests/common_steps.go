/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddtests

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/hyperledger/fabric-protos-go/common"
	fabricCommon "github.com/hyperledger/fabric-protos-go/common"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel/invoke"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/status"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
	contextApi "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	fabApi "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	mspApi "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	contextImpl "github.com/hyperledger/fabric-sdk-go/pkg/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/gopackager"
	"github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/common/policydsl"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
)

// CommonSteps contain BDDContext
type CommonSteps struct {
	BDDContext *BDDContext
}

type Peers []*PeerConfig

func (p Peers) Shuffle() Peers {
	var peers Peers
	for _, i := range rand.Perm(len(p)) {
		peers = append(peers, p[i])
	}
	return peers
}

var logger = logging.NewLogger("test-logger")

const (
	authHeader  = "Authorization"
	tokenPrefix = "Bearer "
)

var queryValue string
var vars = make(map[string]string)

type HTTPPath = string
type HTTPMethod = string
type AuthToken = string

var authTokenMap = make(map[HTTPPath]map[HTTPMethod]AuthToken)

type queryInfoResponse struct {
	Height            string
	CurrentBlockHash  string
	PreviousBlockHash string
}

var ccCodesForRetry = []int32{404}

// TODO: status.ConnectionFailed should be added to the fabric-sdk-go as retryable
var resMgmtRetryableCodes = func() map[status.Group][]status.Code {
	codes := retry.ResMgmtDefaultRetryableCodes
	codes[status.EndorserClientStatus] = append(codes[status.EndorserClientStatus], status.ConnectionFailed)
	return codes
}

var resMgmtRetryOpts = retry.Opts{
	Attempts:       50,
	InitialBackoff: 500 * time.Millisecond,
	MaxBackoff:     5 * time.Second,
	BackoffFactor:  2,
	RetryableCodes: resMgmtRetryableCodes(),
}

// NewCommonSteps create new CommonSteps struct
func NewCommonSteps(context *BDDContext) *CommonSteps {
	//grpclog.SetLogger(logger)
	return &CommonSteps{BDDContext: context}
}

// GetDeployPath ..
func (d *CommonSteps) getDeployPath(ccType string) string {
	// test cc come from fixtures
	pwd, _ := os.Getwd()

	switch ccType {
	case "test":
		return path.Join(pwd, d.BDDContext.testCCPath)
	case "system":
		return path.Join(pwd, d.BDDContext.systemCCPath)
	default:
		panic(fmt.Sprintf("unsupported chaincode type: [%s]", ccType))
	}
}

func (d *CommonSteps) displayBlockFromChannel(blockNum int, channelID string) error {
	block, err := d.getBlocks(channelID, blockNum, 1)
	if err != nil {
		return err
	}
	logger.Infof("%s\n", block)
	return nil
}

func (d *CommonSteps) getBlocks(channelID string, blockNum, numBlocks int) (string, error) {
	orgID, err := d.BDDContext.OrgIDForChannel(channelID)
	if err != nil {
		return "", err
	}

	strBlockNum := fmt.Sprintf("%d", blockNum)
	strNumBlocks := fmt.Sprintf("%d", numBlocks)
	return NewFabCLI().Exec("query", "block", "--config", d.BDDContext.clientConfigFilePath+d.BDDContext.clientConfigFileName, "--cid", channelID, "--orgid", orgID, "--num", strBlockNum, "--traverse", strNumBlocks)
}

func (d *CommonSteps) displayBlocksFromChannel(numBlocks int, channelID string) error {
	height, err := d.getChannelBlockHeight(channelID)
	if err != nil {
		return fmt.Errorf("error getting channel height: %s", err)
	}

	block, err := d.getBlocks(channelID, height-1, numBlocks)
	if err != nil {
		return err
	}

	logger.Infof("%s\n", block)

	return nil
}

func (d *CommonSteps) getChannelBlockHeight(channelID string) (int, error) {
	orgID, err := d.BDDContext.OrgIDForChannel(channelID)
	if err != nil {
		return 0, err
	}

	resp, err := NewFabCLI().GetJSON("query", "info", "--config", d.BDDContext.clientConfigFilePath+d.BDDContext.clientConfigFileName, "--cid", channelID, "--orgid", orgID)
	if err != nil {
		return 0, err
	}

	var info queryInfoResponse
	if err := json.Unmarshal([]byte(resp), &info); err != nil {
		return 0, fmt.Errorf("Error unmarshalling JSON response: %s", err)
	}

	return strconv.Atoi(info.Height)
}

func (d *CommonSteps) displayLastBlockFromChannel(channelID string) error {
	return d.displayBlocksFromChannel(1, channelID)
}

func (d *CommonSteps) wait(seconds int) error {
	logger.Infof("Waiting [%d] seconds\n", seconds)
	time.Sleep(time.Duration(seconds) * time.Second)
	return nil
}

func (d *CommonSteps) createChannelAndJoinAllPeers(channelID string) error {
	return d.createChannelAndJoinPeers(channelID, d.BDDContext.Orgs())
}

func (d *CommonSteps) createChannelAndJoinPeersFromOrg(channelID, orgs string) error {
	orgList := strings.Split(orgs, ",")
	if len(orgList) == 0 {
		return fmt.Errorf("must specify at least one org ID")
	}
	return d.createChannelAndJoinPeers(channelID, orgList)
}

func (d *CommonSteps) createChannelAndJoinPeers(channelID string, orgs []string) error {
	logger.Infof("Creating channel [%s] and joining all peers from orgs %s", channelID, orgs)
	if len(orgs) == 0 {
		return fmt.Errorf("no orgs specified")
	}

	for _, orgID := range orgs {
		peersConfig, ok := d.BDDContext.clientConfig.PeersConfig(orgID)
		if !ok {
			return fmt.Errorf("could not get peers config for org [%s]", orgID)
		}
		if len(peersConfig) == 0 {
			return fmt.Errorf("no peers for org [%s]", orgID)
		}
		if err := d.joinPeersToChannel(channelID, orgID, peersConfig); err != nil {
			return fmt.Errorf("error joining peer to channel: %s", err)
		}

	}

	return nil
}

func (d *CommonSteps) joinPeersToChannel(channelID, orgID string, peersConfig []fabApi.PeerConfig) error {

	for _, peerConfig := range peersConfig {
		serverHostOverride := ""
		if str, ok := peerConfig.GRPCOptions["ssl-target-name-override"].(string); ok {
			serverHostOverride = str
		}
		d.BDDContext.AddPeerConfigToChannel(&PeerConfig{Config: peerConfig, OrgID: orgID, MspID: d.BDDContext.peersMspID[serverHostOverride], PeerID: serverHostOverride}, channelID)
	}
	peer, err := d.BDDContext.OrgUserContext(orgID, ADMIN).InfraProvider().CreatePeerFromConfig(&fabApi.NetworkPeer{PeerConfig: peersConfig[0]})
	if err != nil {
		return errors.WithMessage(err, "NewPeer failed")
	}
	resourceMgmt := d.BDDContext.ResMgmtClient(orgID, ADMIN)

	// Check if primary peer has joined channel
	alreadyJoined, err := HasPrimaryPeerJoinedChannel(channelID, resourceMgmt, d.BDDContext.OrgUserContext(orgID, ADMIN), peer)
	if err != nil {
		return fmt.Errorf("Error while checking if primary peer has already joined channel: %s", err)
	} else if alreadyJoined {
		logger.Infof("alreadyJoined orgID [%s]\n", orgID)
		return nil
	}

	if d.BDDContext.ChannelCreated(channelID) == false {
		// only the first peer of the first org can create a channel
		logger.Infof("Creating channel [%s]\n", channelID)
		txPath := GetChannelTxPath(channelID)
		if txPath == "" {
			return fmt.Errorf("channel TX path not found for channel: %s", channelID)
		}

		// Create and join channel
		req := resmgmt.SaveChannelRequest{ChannelID: channelID,
			ChannelConfigPath: txPath,
			SigningIdentities: []mspApi.SigningIdentity{d.BDDContext.OrgUserContext(orgID, ADMIN)}}

		if _, err = resourceMgmt.SaveChannel(req, resmgmt.WithRetry(resMgmtRetryOpts)); err != nil {
			return errors.WithMessage(err, "SaveChannel failed")
		}
	}

	logger.Infof("Updating anchor peers for org [%s] on channel [%s]\n", orgID, channelID)

	// Update anchors for peer org
	anchorTxPath := GetChannelAnchorTxPath(channelID, orgID)
	if anchorTxPath == "" {
		return fmt.Errorf("anchor TX path not found for channel [%s] and org [%s]", channelID, orgID)
	}
	// Create channel (or update if it already exists)
	req := resmgmt.SaveChannelRequest{ChannelID: channelID,
		ChannelConfigPath: anchorTxPath,
		SigningIdentities: []mspApi.SigningIdentity{d.BDDContext.OrgUserContext(orgID, ADMIN)}}

	if _, err := resourceMgmt.SaveChannel(req, resmgmt.WithRetry(resMgmtRetryOpts)); err != nil {
		return errors.WithMessage(err, "SaveChannel failed")
	}

	d.BDDContext.createdChannels[channelID] = true

	// Join Channel without error for anchor peers only. ignore JoinChannel error for other peers as AnchorePeer with JoinChannel will add all org's peers

	resMgmtClient := d.BDDContext.ResMgmtClient(orgID, ADMIN)
	if err = resMgmtClient.JoinChannel(channelID, resmgmt.WithRetry(resMgmtRetryOpts)); err != nil {
		return fmt.Errorf("JoinChannel returned error: %s", err)
	}

	return nil
}

// InvokeCConOrg invoke cc on org
func (d *CommonSteps) InvokeCConOrg(ccID, args, orgIDs, channelID string) error {
	argArr, err := ResolveAllVars(args)
	if err != nil {
		return err
	}
	if _, err := d.InvokeCCWithArgs(ccID, channelID, "", d.OrgPeers(orgIDs, channelID), argArr, nil); err != nil {
		return fmt.Errorf("InvokeCCWithArgs return error: %s", err)
	}
	return nil
}

// InvokeCC invoke cc
func (d *CommonSteps) InvokeCC(ccID, args, channelID string) error {
	argArr, err := ResolveAllVars(args)
	if err != nil {
		return err
	}
	if _, err := d.InvokeCCWithArgs(ccID, channelID, "", nil, argArr, nil); err != nil {
		return fmt.Errorf("InvokeCC return error: %s", err)
	}
	return nil
}

// orgClientInvokesCC a client in the given org invokes a chaincode
func (d *CommonSteps) orgClientInvokesCC(clientOrgID, ccID, args, channelID string) error {
	argArr, err := ResolveAllVars(args)
	if err != nil {
		return err
	}
	if _, err := d.InvokeCCWithArgs(ccID, channelID, clientOrgID, nil, argArr, nil); err != nil {
		return fmt.Errorf("InvokeCC return error: %s", err)
	}
	return nil
}

func (d *CommonSteps) orgClientInvokesCCWithExpectedError(clientOrgID, ccID, args, channelID, expectedErr string) error {
	argArr, err := ResolveAllVars(args)
	if err != nil {
		return err
	}

	_, err = d.InvokeCCWithArgs(ccID, channelID, clientOrgID, nil, argArr, nil)
	if err == nil {
		return fmt.Errorf("expecting error [%s] but received none", expectedErr)
	}

	if !strings.Contains(err.Error(), expectedErr) {
		return fmt.Errorf("expecting error [%s] to contain [%s]", err.Error(), expectedErr)
	}

	return nil
}

//InvokeCCWithArgsAsAdmin invoke cc with args as admin user type
func (d *CommonSteps) InvokeCCWithArgsAsAdmin(ccID, channelID string, targets []*PeerConfig, args []string, transientData map[string][]byte) (channel.Response, error) {
	return d.invokeCCWithArgs(ccID, channelID, "", targets, args, transientData, ADMIN)
}

//InvokeCCWithArgs invoke cc with args as regular user
func (d *CommonSteps) InvokeCCWithArgs(ccID, channelID, clientOrgID string, targets []*PeerConfig, args []string, transientData map[string][]byte) (channel.Response, error) {
	return d.invokeCCWithArgs(ccID, channelID, clientOrgID, targets, args, transientData, USER)
}

// invokeCCWithArgs ...
func (d *CommonSteps) invokeCCWithArgs(ccID, channelID, clientOrgID string, targets []*PeerConfig, args []string, transientData map[string][]byte, userType string) (channel.Response, error) {
	var peers []fabApi.Peer

	for _, target := range targets {
		if clientOrgID == "" {
			clientOrgID = targets[0].OrgID
		}

		targetPeer, err := d.BDDContext.OrgUserContext(targets[0].OrgID, ADMIN).InfraProvider().CreatePeerFromConfig(&fabApi.NetworkPeer{PeerConfig: target.Config})
		if err != nil {
			return channel.Response{}, errors.WithMessage(err, "NewPeer failed")
		}
		peers = append(peers, targetPeer)
	}

	if clientOrgID == "" {
		clientOrgID = d.BDDContext.orgs[0]
	}

	chClient, err := d.BDDContext.OrgChannelClient(clientOrgID, userType, channelID)
	if err != nil {
		return channel.Response{}, fmt.Errorf("Failed to create new channel client: %s", err)
	}

	retryOpts := retry.DefaultChannelOpts

	for _, code := range ccCodesForRetry {
		addRetryCode(retryOpts.RetryableCodes, status.ChaincodeStatus, status.Code(code))
	}

	response, err := chClient.Execute(
		channel.Request{
			ChaincodeID: ccID,
			Fcn:         args[0],
			Args:        GetByteArgs(args[1:]),
		},
		channel.WithTargets(peers...),
		channel.WithRetry(retryOpts),
	)

	if err != nil {
		return channel.Response{}, fmt.Errorf("InvokeChaincode return error: %s", err)
	}

	queryValue = string(response.Payload)

	return response, nil
}

// addRetryCode adds the given group and code to the given map
func addRetryCode(codes map[status.Group][]status.Code, group status.Group, code status.Code) {
	g, exists := codes[group]
	if !exists {
		g = []status.Code{}
	}
	codes[group] = append(g, code)
}

func (d *CommonSteps) queryCConOrg(ccID, args, orgIDs, channelID string) error {
	queryValue = ""

	argArr, err := ResolveAllVars(args)
	if err != nil {
		return err
	}

	queryValue, err = d.QueryCCWithArgs(false, ccID, channelID, "", argArr, nil, d.OrgPeers(orgIDs, channelID)...)
	if err != nil {
		return fmt.Errorf("QueryCCWithArgs return error: %s", err)
	}
	logger.Debugf("QueryCCWithArgs return value: [%s]", queryValue)
	return nil
}

func (d *CommonSteps) queryCConTargetPeers(ccID, args, peerIDs, channelID string) error {
	queryValue = ""

	if peerIDs == "" {
		return errors.New("no target peers specified")
	}

	targetPeers, err := d.Peers(peerIDs)
	if err != nil {
		return err
	}

	logger.Debugf("Querying peers [%s]...", targetPeers)

	argArr, err := ResolveAllVars(args)
	if err != nil {
		return err
	}

	queryValue, err = d.QueryCCWithArgs(false, ccID, channelID, "", argArr, nil, targetPeers...)
	if err != nil {
		return fmt.Errorf("QueryCCWithArgs return error: %s", err)
	}
	logger.Debugf("QueryCCWithArgs return value: [%s]", queryValue)
	return nil
}

func (d *CommonSteps) invokeCConTargetPeers(ccID, args, peerIDs, channelID string) error {
	queryValue = ""

	if peerIDs == "" {
		return errors.New("no target peers specified")
	}

	targetPeers, err := d.Peers(peerIDs)
	if err != nil {
		return err
	}

	logger.Debugf("Invoking peers [%s]...", targetPeers)

	argArr, err := ResolveAllVars(args)
	if err != nil {
		return err
	}

	resp, err := d.InvokeCCWithArgs(ccID, channelID, "", targetPeers, argArr, nil)
	if err != nil {
		return fmt.Errorf("InvokeCCWithArgs returned error: %s", err)
	}
	queryValue = string(resp.Payload)
	logger.Debugf("InvokeCCWithArgs returned value: [%s]", queryValue)
	return nil
}

func (d *CommonSteps) queryCConSinglePeerInOrg(ccID, args, orgIDs, channelID string) error {
	return d.doQueryCConSinglePeerInOrg(ccID, args, orgIDs, channelID, "")
}

func (d *CommonSteps) orgClientQueriesCConSinglePeerInOrg(clientOrgID, ccID, args, orgIDs, channelID string) error {
	return d.doQueryCConSinglePeerInOrg(ccID, args, orgIDs, channelID, clientOrgID)
}

func (d *CommonSteps) doQueryCConSinglePeerInOrg(ccID, args, orgIDs, channelID, clientOrgID string) error {
	queryValue = ""

	targetPeers := d.OrgPeers(orgIDs, channelID)
	if len(targetPeers) == 0 {
		return errors.Errorf("no peers in org(s) [%s] for channel [%s]", orgIDs, channelID)
	}

	// Pick a random peer
	targetPeer := targetPeers.Shuffle()[0]

	logger.Infof("Querying peer [%s]...", targetPeer.Config.URL)

	argArr, err := ResolveAllVars(args)
	if err != nil {
		return err
	}

	queryValue, err = d.QueryCCWithArgs(false, ccID, channelID, clientOrgID, argArr, nil, targetPeer)
	if err != nil {
		return fmt.Errorf("QueryCCWithArgs return error: %s", err)
	}
	logger.Debugf("QueryCCWithArgs return value: [%s]", queryValue)
	return nil
}

func (d *CommonSteps) querySystemCC(ccID, args, orgID, channelID string) error {
	queryValue = ""

	peersConfig, ok := d.BDDContext.clientConfig.PeersConfig(orgID)
	if !ok {
		return fmt.Errorf("could not get peers config for org [%s]", orgID)
	}

	serverHostOverride := ""
	if str, ok := peersConfig[0].GRPCOptions["ssl-target-name-override"].(string); ok {
		serverHostOverride = str
	}

	argsArray, err := ResolveAllVars(args)
	if err != nil {
		return err
	}

	queryValue, err = d.QueryCCWithArgs(true, ccID, channelID, "", argsArray, nil,
		[]*PeerConfig{{Config: peersConfig[0], OrgID: orgID, MspID: d.BDDContext.peersMspID[serverHostOverride], PeerID: serverHostOverride}}...)
	if err != nil {
		return fmt.Errorf("QueryCCWithArgs return error: %s", err)
	}

	logger.Debugf("QueryCCWithArgs return value: [%s]", queryValue)

	return nil
}

func (d *CommonSteps) querySystemCCWithError(ccID, args, orgID, channelID, expectedError string) error {
	queryValue = ""

	peersConfig, ok := d.BDDContext.clientConfig.PeersConfig(orgID)
	if !ok {
		return fmt.Errorf("could not get peers config for org [%s]", orgID)
	}

	serverHostOverride := ""
	if str, ok := peersConfig[0].GRPCOptions["ssl-target-name-override"].(string); ok {
		serverHostOverride = str
	}

	argsArray, err := ResolveAllVars(args)
	if err != nil {
		return err
	}

	queryValue, err = d.QueryCCWithArgs(true, ccID, channelID, "", argsArray, nil,
		[]*PeerConfig{{Config: peersConfig[0], OrgID: orgID, MspID: d.BDDContext.peersMspID[serverHostOverride], PeerID: serverHostOverride}}...)
	if err == nil {
		return errors.Errorf("expecting error [%s] but got no error", expectedError)
	}

	logger.Infof("querySystemCCWithError returned error: [%s]", err)

	if !strings.Contains(err.Error(), expectedError) {
		return errors.Errorf("expecting error [%s] but got [%s]", expectedError, err)
	}

	return nil
}

func (d *CommonSteps) queryCC(ccID, args, channelID string) error {
	logger.Infof("Querying chaincode [%s] on channel [%s] with args [%s]", ccID, channelID, args)

	queryValue = ""

	argArr, err := ResolveAllVars(args)
	if err != nil {
		return err
	}

	queryValue, err = d.QueryCCWithArgs(false, ccID, channelID, "", argArr, nil)
	if err != nil {
		return fmt.Errorf("QueryCCWithArgs return error: %s", err)
	}
	logger.Infof("QueryCC return value: [%s]", queryValue)
	return nil
}

func (d *CommonSteps) queryCCWithError(ccID, args, channelID string, expectedError string) error {
	err := d.queryCC(ccID, args, channelID)
	if err == nil {
		return errors.Errorf("expecting error [%s] but got no error", expectedError)
	}

	if !strings.Contains(err.Error(), expectedError) {
		return errors.Errorf("expecting error [%s] but got [%s]", expectedError, err)
	}

	return nil
}

// QueryCCWithArgs ...
func (d *CommonSteps) QueryCCWithArgs(systemCC bool, ccID, channelID, clientOrgID string, args []string, transientData map[string][]byte, targets ...*PeerConfig) (string, error) {
	return d.QueryCCWithOpts(systemCC, ccID, channelID, clientOrgID, args, 0, true, 0, transientData, targets...)
}

// QueryCCWithOpts ...
func (d *CommonSteps) QueryCCWithOpts(systemCC bool, ccID, channelID, clientOrgID string, args []string, timeout time.Duration, concurrent bool, interval time.Duration, transientData map[string][]byte, targets ...*PeerConfig) (string, error) {
	var peers []fabApi.Peer
	var queryResult string
	for _, target := range targets {
		if clientOrgID == "" {
			clientOrgID = target.OrgID
		}

		targetPeer, err := d.BDDContext.OrgUserContext(target.OrgID, ADMIN).InfraProvider().CreatePeerFromConfig(&fabApi.NetworkPeer{PeerConfig: target.Config})
		if err != nil {
			return "", errors.WithMessage(err, "NewPeer failed")
		}

		peers = append(peers, targetPeer)
	}

	if clientOrgID == "" {
		clientOrgID = d.BDDContext.orgs[0]
	}

	chClient, err := d.BDDContext.OrgChannelClient(clientOrgID, ADMIN, channelID)
	if err != nil {
		logger.Errorf("Failed to create new channel client: %s", err)
		return "", errors.Wrap(err, "Failed to create new channel client")
	}

	retryOpts := retry.DefaultChannelOpts
	retryOpts.RetryableCodes = retry.ChannelClientRetryableCodes

	for _, code := range ccCodesForRetry {
		addRetryCode(retryOpts.RetryableCodes, status.ChaincodeStatus, status.Code(code))
	}

	if systemCC {
		// Create a system channel client

		systemHandlerChain := invoke.NewProposalProcessorHandler(
			NewCustomEndorsementHandler(
				d.BDDContext.OrgUserContext(clientOrgID, USER),
				invoke.NewEndorsementValidationHandler(),
			))

		resp, err := chClient.InvokeHandler(systemHandlerChain, channel.Request{
			ChaincodeID:  ccID,
			Fcn:          args[0],
			Args:         GetByteArgs(args[1:]),
			TransientMap: transientData,
		}, channel.WithTargets(peers...), channel.WithTimeout(fabApi.Execute, timeout), channel.WithRetry(retryOpts))
		if err != nil {
			return "", fmt.Errorf("QueryChaincode return error: %s", err)
		}
		queryResult = string(resp.Payload)
		return queryResult, nil
	}

	if concurrent {

		resp, err := chClient.Query(channel.Request{
			ChaincodeID:  ccID,
			Fcn:          args[0],
			Args:         GetByteArgs(args[1:]),
			TransientMap: transientData,
		}, channel.WithTargets(peers...), channel.WithTimeout(fabApi.Execute, timeout), channel.WithRetry(retryOpts))
		if err != nil {
			return "", fmt.Errorf("QueryChaincode return error: %s", err)
		}
		queryResult = string(resp.Payload)

	} else {
		var errs []error
		for _, peer := range peers {
			if len(args) > 0 && args[0] == "warmup" {
				logger.Infof("Warming up chaincode [%s] on peer [%s] in channel [%s]", ccID, peer.URL(), channelID)
			}
			resp, err := chClient.Query(channel.Request{
				ChaincodeID:  ccID,
				Fcn:          args[0],
				Args:         GetByteArgs(args[1:]),
				TransientMap: transientData,
			}, channel.WithTargets([]fabApi.Peer{peer}...), channel.WithTimeout(fabApi.Execute, timeout), channel.WithRetry(retryOpts))
			if err != nil {
				errs = append(errs, err)
			} else {
				queryResult = string(resp.Payload)
			}
			if interval > 0 {
				logger.Infof("Waiting %s\n", interval)
				time.Sleep(interval)
			}
		}
		if len(errs) > 0 {
			return "", fmt.Errorf("QueryChaincode return error: %s", errs[0])
		}
	}

	logger.Debugf("QueryChaincode return value: [%s]", queryResult)
	return queryResult, nil
}

func (d *CommonSteps) containsInQueryValue(ccID string, value string) error {
	logger.Infof("Query value %s and tested value %s", queryValue, value)
	if !strings.Contains(queryValue, value) {
		return fmt.Errorf("Query value(%s) doesn't contain expected value(%s)", queryValue, value)
	}
	return nil
}

func (d *CommonSteps) equalQueryValue(ccID string, value string) error {
	if err := ResolveVarsInExpression(&ccID, &value); err != nil {
		return err
	}

	logger.Infof("Query value %s and tested value %s", queryValue, value)
	if queryValue == value {
		return nil
	}

	return fmt.Errorf("Query value(%s) doesn't equal expected value(%s)", queryValue, value)
}

func (d *CommonSteps) responseEquals(value string) error {
	if queryValue == value {
		logger.Infof("Response equals expected value [%s]", value)
		return nil
	}

	return fmt.Errorf("Reponse [%s] does not equal expected value [%s]", queryValue, value)
}

func (d *CommonSteps) setVariableFromCCResponse(key string) error {
	logger.Infof("Saving value %s to variable %s", queryValue, key)
	SetVar(key, queryValue)
	return nil
}

func (d *CommonSteps) setJSONVariable(varName, value string) error {
	m := make(map[string]interface{})
	var bytes []byte

	if err := json.Unmarshal([]byte(value), &m); err != nil {
		var arr []interface{}
		if err := json.Unmarshal([]byte(value), &arr); err != nil {
			return errors.WithMessagef(err, "invalid JSON: %s", value)
		}

		arr, err = resolveArray(arr)
		if err != nil {
			return err
		}

		bytes, err = json.Marshal(arr)
		if err != nil {
			return err
		}
	} else {
		doc, err := resolveMap(m)
		if err != nil {
			return err
		}

		bytes, err = json.Marshal(doc)
		if err != nil {
			return err
		}
	}

	SetVar(varName, string(bytes))

	return nil
}

func (d *CommonSteps) jsonPathOfCCResponseEquals(path, expected string) error {
	resolved, err := ResolveVars(expected)
	if err != nil {
		return err
	}

	expected = resolved.(string)

	r := gjson.Get(queryValue, path)

	logger.Infof("Path [%s] of JSON %s resolves to %s", path, queryValue, r.Str)
	if r.Str == expected {
		return nil
	}

	return fmt.Errorf("JSON path resolves to [%s] which is not the expected value [%s]", r.Str, expected)
}

func (d *CommonSteps) jsonPathOfNumericResponseEquals(path, expected string) error {
	resolved, err := ResolveVars(expected)
	if err != nil {
		return err
	}

	expected = resolved.(string)

	r := gjson.Get(queryValue, path)

	logger.Infof("Path [%s] of JSON %s resolves to %g", path, queryValue, r.Num)

	strNum := strconv.FormatFloat(r.Num, 'f', -1, 64)
	if strNum == expected {
		return nil
	}

	return fmt.Errorf("JSON path resolves to [%g] which is not the expected value [%s]", r.Num, expected)
}

func (d *CommonSteps) jsonPathOfBoolResponseEquals(path, expected string) error {
	resolved, err := ResolveVars(expected)
	if err != nil {
		return err
	}

	expected = resolved.(string)

	r := gjson.Get(queryValue, path)

	logger.Infof("Path [%s] of JSON %s resolves to %t", path, queryValue, r.Bool())

	strBool := strconv.FormatBool(r.Bool())
	if strBool == expected {
		return nil
	}

	return fmt.Errorf("JSON path resolves to [%s] which is not the expected value [%s]", strBool, expected)
}

func (d *CommonSteps) jsonPathOfCCHasNumItems(path string, expectedNum int) error {
	r := gjson.Get(queryValue, path)
	logger.Infof("Path [%s] of JSON %s resolves to %d items", path, queryValue, int(r.Num))
	if int(r.Num) == expectedNum {
		return nil
	}
	return fmt.Errorf("JSON path resolves to [%d] items which is not the expected number of items [%d]", int(r.Num), expectedNum)
}

func (d *CommonSteps) jsonPathOfCCResponseContains(path, expected string) error {
	resolved, err := ResolveVars(expected)
	if err != nil {
		return err
	}

	expected = resolved.(string)

	r := gjson.Get(queryValue, path)

	logger.Infof("Path [%s] of JSON %s resolves to %s", path, queryValue, r.Raw)

	for _, a := range r.Array() {
		if a.Str == expected {
			return nil
		}
	}

	return fmt.Errorf("JSON path resolves to [%s] which is not the expected value [%s]", r.Array(), expected)
}

func (d *CommonSteps) jsonPathOfResponseNotContains(path, notExpected string) error {
	resolved, err := ResolveVars(notExpected)
	if err != nil {
		return err
	}

	notExpected = resolved.(string)

	r := gjson.Get(queryValue, path)

	logger.Infof("Path [%s] of JSON %s resolves to %s", path, queryValue, r.Raw)

	for _, a := range r.Array() {
		if a.Str == notExpected {
			return fmt.Errorf("JSON path resolves to [%s] which contains value [%s]", r.Array(), notExpected)
		}
	}

	return nil
}

func (d *CommonSteps) jsonPathOfResponseSavedToVar(path, varName string) error {
	r := gjson.Get(queryValue, path)

	logger.Infof("Path [%s] of JSON %s resolves to %s. Saving to variable [%s]", path, queryValue, r.Str, varName)

	SetVar(varName, r.Str)

	return nil
}

func (d *CommonSteps) jsonPathOfNumericResponseSavedToVar(path, varName string) error {
	r := gjson.Get(queryValue, path)

	logger.Infof("Path [%s] of JSON %s resolves to %g. Saving to variable [%s]", path, queryValue, r.Num, varName)

	SetVar(varName, strconv.FormatFloat(r.Num, 'f', -1, 64))

	return nil
}

func (d *CommonSteps) jsonPathOfRawResponseSavedToVar(path, varName string) error {
	r := gjson.Get(queryValue, path)

	logger.Infof("Path [%s] of JSON %s resolves to %s. Saving to variable [%s]", path, queryValue, r.Raw, varName)

	SetVar(varName, r.Raw)

	return nil
}

func (d *CommonSteps) jsonPathOfBoolResponseSavedToVar(path, varName string) error {
	r := gjson.Get(queryValue, path)

	logger.Infof("Path [%s] of JSON %s resolves to %t. Saving to variable [%s]", path, queryValue, r.Bool(), varName)

	SetVar(varName, strconv.FormatBool(r.Bool()))

	return nil
}

func (d *CommonSteps) jsonPathOfResponseNotEmpty(path string) error {
	r := gjson.Get(queryValue, path)

	logger.Infof("Path [%s] of JSON %s resolves to %s", path, queryValue, r.Str)
	if len(r.Str) > 0 {
		return nil
	}

	return fmt.Errorf("JSON path resolves to an empty value")
}

func (d *CommonSteps) jsonPathOfArrayResponseNotEmpty(path string) error {
	r := gjson.Get(queryValue, path)

	logger.Infof("Path [%s] of JSON %s resolves to %s", path, queryValue, r.Array())

	if len(r.Array()) > 0 {
		logger.Infof("Path [%s] of JSON %s resolves to %d array elements", path, queryValue, len(r.Array()))

		return nil
	}

	return fmt.Errorf("JSON path [%s] resolves to an empty array", path)
}

func (d *CommonSteps) installChaincodeToAllPeers(ccType, ccID, ccPath string) error {
	logger.Infof("Installing chaincode [%s] from path [%s] to all peers", ccID, ccPath)
	return d.doInstallChaincodeToOrg(ccType, ccID, ccPath, "v1", "", "")
}

func (d *CommonSteps) installChaincodeToAllPeersWithVersion(ccType, ccID, ccVersion, ccPath string) error {
	logger.Infof("Installing chaincode [%s:%s] from path [%s] to all peers", ccID, ccVersion, ccPath)
	return d.doInstallChaincodeToOrg(ccType, ccID, ccPath, ccVersion, "", "")
}

func (d *CommonSteps) installChaincodeToAllPeersExcept(ccType, ccID, ccPath, blackListRegex string) error {
	logger.Infof("Installing chaincode [%s] from path [%s] to all peers except [%s]", ccID, ccPath, blackListRegex)
	return d.doInstallChaincodeToOrg(ccType, ccID, ccPath, "v1", "", blackListRegex)
}

func (d *CommonSteps) instantiateChaincode(ccType, ccID, ccPath, channelID, args, ccPolicy, collectionNames string) error {
	logger.Infof("Preparing to instantiate chaincode [%s] from path [%s] on channel [%s] with args [%s] and CC policy [%s] and collectionPolicy [%s]", ccID, ccPath, channelID, args, ccPolicy, collectionNames)
	return d.instantiateChaincodeWithOpts(ccType, ccID, ccPath, "", channelID, args, ccPolicy, collectionNames, false)
}

func (d *CommonSteps) upgradeChaincode(ccType, ccID, ccVersion, ccPath, channelID, args, ccPolicy, collectionNames string) error {
	logger.Infof("Preparing to instantiate chaincode [%s] from path [%s] on channel [%s] with args [%s] and CC policy [%s] and collectionPolicy [%s]", ccID, ccPath, channelID, args, ccPolicy, collectionNames)
	return d.upgradeChaincodeWithOpts(ccType, ccID, ccVersion, ccPath, "", channelID, args, ccPolicy, collectionNames, false)
}

func (d *CommonSteps) upgradeChaincodeWithError(ccType, ccID, ccVersion, ccPath, channelID, args, ccPolicy, collectionNames, expectedError string) error {
	logger.Infof("Preparing to instantiate chaincode [%s] from path [%s] on channel [%s] with args [%s] and CC policy [%s] and collectionPolicy [%s]. Expected error [%s]", ccID, ccPath, channelID, args, ccPolicy, collectionNames, expectedError)
	err := d.upgradeChaincodeWithOpts(ccType, ccID, ccVersion, ccPath, "", channelID, args, ccPolicy, collectionNames, false)
	if err == nil {
		return errors.Errorf("expecting error [%s] but got no error", expectedError)
	}
	if !strings.Contains(err.Error(), expectedError) {
		return errors.Errorf("expecting error [%s] but got [%s]", expectedError, err)
	}
	return nil
}

func (d *CommonSteps) instantiateChaincodeOnOrg(ccType, ccID, ccPath, orgIDs, channelID, args, ccPolicy, collectionNames string) error {
	logger.Infof("Preparing to instantiate chaincode [%s] from path [%s] to orgs [%s] on channel [%s] with args [%s] and CC policy [%s] and collectionPolicy [%s]", ccID, ccPath, orgIDs, channelID, args, ccPolicy, collectionNames)
	return d.instantiateChaincodeWithOpts(ccType, ccID, ccPath, orgIDs, channelID, args, ccPolicy, collectionNames, false)
}

func (d *CommonSteps) deployChaincode(ccType, ccID, ccPath, channelID, args, ccPolicy, collectionPolicy string) error {
	logger.Infof("Installing and instantiating chaincode [%s] from path [%s] to channel [%s] with args [%s] and CC policy [%s] and collectionPolicy [%s]", ccID, ccPath, channelID, args, ccPolicy, collectionPolicy)
	return d.deployChaincodeToOrg(ccType, ccID, ccPath, "", channelID, args, ccPolicy, collectionPolicy)
}

func (d *CommonSteps) installChaincodeToOrg(ccType, ccID, ccPath, orgIDs string) error {
	return d.doInstallChaincodeToOrg(ccType, ccID, ccPath, "v1", orgIDs, "")
}

func (d *CommonSteps) doInstallChaincodeToOrg(ccType, ccID, ccPath, ccVersion, orgIDs, blackListRegex string) error {
	logger.Infof("Preparing to install chaincode [%s:%s] from path [%s] to orgs [%s] - Blacklisted peers: [%s]", ccID, ccPath, ccVersion, orgIDs, blackListRegex)

	var oIDs []string
	if orgIDs != "" {
		oIDs = strings.Split(orgIDs, ",")
	} else {
		oIDs = d.BDDContext.orgs
	}

	for _, orgID := range oIDs {
		targets, err := d.getLocalTargets(orgID, blackListRegex)
		if err != nil {
			return err
		}

		resMgmtClient := d.BDDContext.ResMgmtClient(orgID, ADMIN)

		ccPkg, err := gopackager.NewCCPackage(ccPath, d.getDeployPath(ccType))
		if err != nil {
			return err
		}

		if len(targets) == 0 {
			return errors.Errorf("no targets for chaincode [%s]", ccID)
		}

		logger.Infof("... installing chaincode [%s] from path [%s] to targets %s", ccID, ccPath, targets)
		_, err = resMgmtClient.InstallCC(
			resmgmt.InstallCCRequest{Name: ccID, Path: ccPath, Version: ccVersion, Package: ccPkg},
			resmgmt.WithRetry(resMgmtRetryOpts),
			resmgmt.WithTargetEndpoints(targets...),
		)
		if err != nil {
			return fmt.Errorf("SendInstallProposal return error: %s", err)
		}
	}
	return nil
}

func (d *CommonSteps) getLocalTargets(orgID string, blackListRegex string) ([]string, error) {
	return getLocalTargets(d.BDDContext, orgID, blackListRegex)
}

func getLocalTargets(context *BDDContext, orgID string, blackListRegex string) ([]string, error) {
	var blacklistedPeersRegex *regexp.Regexp
	if blackListRegex != "" {
		var err error
		blacklistedPeersRegex, err = regexp.Compile(blackListRegex)
		if err != nil {
			return nil, err
		}
	}

	contextProvider := func() (contextApi.Client, error) {
		return context.OrgUserContext(orgID, ADMIN), nil
	}

	localContext, err := contextImpl.NewLocal(contextProvider)
	if err != nil {
		return nil, err
	}

	peers, err := localContext.LocalDiscoveryService().GetPeers()
	if err != nil {
		return nil, err
	}

	var peerURLs []string
	for _, peer := range peers {
		peerConfig := context.PeerConfigForURL(peer.URL())
		if peerConfig == nil {
			logger.Warnf("Peer config not found for URL [%s]", peer.URL())
			continue
		}
		if blacklistedPeersRegex != nil && blacklistedPeersRegex.MatchString(peerConfig.PeerID) {
			logger.Infof("Not returning local peer [%s] since it is blacklisted", peerConfig.PeerID)
			continue
		}
		peerURLs = append(peerURLs, peer.URL())
	}

	return peerURLs, nil
}

func (d *CommonSteps) instantiateChaincodeWithOpts(ccType, ccID, ccPath, orgIDs, channelID, args, ccPolicy, collectionNames string, allPeers bool) error {
	logger.Infof("Preparing to instantiate chaincode [%s] from path [%s] to orgs [%s] on channel [%s] with args [%s] and CC policy [%s] and collectionPolicy [%s]", ccID, ccPath, orgIDs, channelID, args, ccPolicy, collectionNames)

	peers := d.OrgPeers(orgIDs, channelID)
	if len(peers) == 0 {
		return errors.Errorf("no peers found for orgs [%s]", orgIDs)
	}
	chaincodePolicy, err := d.newChaincodePolicy(ccPolicy, channelID)
	if err != nil {
		return fmt.Errorf("error creating endorsement policy: %s", err)
	}

	var sdkPeers []fabApi.Peer
	var orgID string

	for _, pconfig := range peers {
		orgID = pconfig.OrgID

		sdkPeer, err := d.BDDContext.OrgUserContext(orgID, ADMIN).InfraProvider().CreatePeerFromConfig(&fabApi.NetworkPeer{PeerConfig: pconfig.Config})
		if err != nil {
			return errors.WithMessage(err, "NewPeer failed")
		}

		sdkPeers = append(sdkPeers, sdkPeer)
		if !allPeers {
			break
		}
	}

	var collConfig []*pb.CollectionConfig
	if collectionNames != "" {
		// Define the private data collection policy config
		for _, collName := range strings.Split(collectionNames, ",") {
			logger.Infof("Configuring collection (%s) for CCID=%s", collName, ccID)
			c, err := d.newCollectionConfig(channelID, collName)
			if err != nil {
				return err
			}
			collConfig = append(collConfig, c)
		}
	}

	resMgmtClient := d.BDDContext.ResMgmtClient(orgID, ADMIN)

	logger.Infof("Instantiating chaincode [%s] from path [%s] on channel [%s] with args [%s] and CC policy [%s] and collectionPolicy [%s] to the following peers: [%s]", ccID, ccPath, channelID, args, ccPolicy, collectionNames, peersAsString(sdkPeers))

	_, err = resMgmtClient.InstantiateCC(
		channelID,
		resmgmt.InstantiateCCRequest{
			Name:       ccID,
			Path:       ccPath,
			Version:    "v1",
			Args:       GetByteArgs(strings.Split(args, ",")),
			Policy:     chaincodePolicy,
			CollConfig: collConfig,
		},
		resmgmt.WithTargets(sdkPeers...),
		resmgmt.WithTimeout(fabApi.Execute, 5*time.Minute),
		resmgmt.WithRetry(resMgmtRetryOpts),
	)

	if err != nil && strings.Contains(err.Error(), "already exists") {
		logger.Warnf("error from InstantiateCC %v", err)
		return nil
	}
	return err
}

func (d *CommonSteps) upgradeChaincodeWithOpts(ccType, ccID, ccVersion, ccPath, orgIDs, channelID, args, ccPolicy, collectionNames string, allPeers bool) error {
	logger.Infof("Preparing to upgrade chaincode [%s:%s] from path [%s] to orgs [%s] on channel [%s] with args [%s] and CC policy [%s] and collectionPolicy [%s]", ccID, ccVersion, ccPath, orgIDs, channelID, args, ccPolicy, collectionNames)

	peers := d.OrgPeers(orgIDs, channelID)
	if len(peers) == 0 {
		return errors.Errorf("no peers found for orgs [%s]", orgIDs)
	}
	chaincodePolicy, err := d.newChaincodePolicy(ccPolicy, channelID)
	if err != nil {
		return fmt.Errorf("error creating endorsement policy: %s", err)
	}

	var sdkPeers []fabApi.Peer
	var orgID string

	for _, pconfig := range peers {
		orgID = pconfig.OrgID

		sdkPeer, err := d.BDDContext.OrgUserContext(orgID, ADMIN).InfraProvider().CreatePeerFromConfig(&fabApi.NetworkPeer{PeerConfig: pconfig.Config})
		if err != nil {
			return errors.WithMessage(err, "NewPeer failed")
		}

		sdkPeers = append(sdkPeers, sdkPeer)
		if !allPeers {
			break
		}
	}

	var collConfig []*pb.CollectionConfig
	if collectionNames != "" {
		// Define the private data collection policy config
		for _, collName := range strings.Split(collectionNames, ",") {
			logger.Infof("Configuring collection (%s) for CCID=%s", collName, ccID)
			c, err := d.newCollectionConfig(channelID, collName)
			if err != nil {
				return err
			}
			collConfig = append(collConfig, c)
		}
	}

	resMgmtClient := d.BDDContext.ResMgmtClient(orgID, ADMIN)

	logger.Infof("Upgrading chaincode [%s] from path [%s] on channel [%s] with args [%s] and CC policy [%s] and collectionPolicy [%s] to the following peers: [%s]", ccID, ccPath, channelID, args, ccPolicy, collectionNames, peersAsString(sdkPeers))

	_, err = resMgmtClient.UpgradeCC(
		channelID,
		resmgmt.UpgradeCCRequest{
			Name:       ccID,
			Path:       ccPath,
			Version:    ccVersion,
			Args:       GetByteArgs(strings.Split(args, ",")),
			Policy:     chaincodePolicy,
			CollConfig: collConfig,
		},
		resmgmt.WithTargets(sdkPeers...),
		resmgmt.WithTimeout(fabApi.Execute, 5*time.Minute),
		resmgmt.WithRetry(resMgmtRetryOpts),
	)

	if err != nil && strings.Contains(err.Error(), "already exists") {
		logger.Warnf("error from InstantiateCC %v", err)
		return nil
	}
	return err
}

func (d *CommonSteps) deployChaincodeToOrg(ccType, ccID, ccPath, orgIDs, channelID, args, ccPolicy, collectionNames string) error {
	logger.Infof("Installing and instantiating chaincode [%s] from path [%s] to orgs [%s] on channel [%s] with args [%s] and CC policy [%s] and collectionPolicy [%s]", ccID, ccPath, orgIDs, channelID, args, ccPolicy, collectionNames)

	peers := d.OrgPeers(orgIDs, channelID)
	if len(peers) == 0 {
		return errors.Errorf("no peers found for orgs [%s]", orgIDs)
	}
	chaincodePolicy, err := d.newChaincodePolicy(ccPolicy, channelID)
	if err != nil {
		return fmt.Errorf("error creating endirsement policy: %s", err)
	}

	var sdkPeers []fabApi.Peer
	var isInstalled bool
	var orgID string

	for _, pconfig := range peers {
		orgID = pconfig.OrgID

		sdkPeer, err := d.BDDContext.OrgUserContext(orgID, ADMIN).InfraProvider().CreatePeerFromConfig(&fabApi.NetworkPeer{PeerConfig: pconfig.Config})
		if err != nil {
			return errors.WithMessage(err, "NewPeer failed")
		}
		resourceMgmt := d.BDDContext.ResMgmtClient(orgID, ADMIN)
		isInstalled, err = IsChaincodeInstalled(resourceMgmt, sdkPeer, ccID)
		if err != nil {
			return fmt.Errorf("Error querying installed chaincodes: %s", err)
		}

		if !isInstalled {

			resMgmtClient := d.BDDContext.ResMgmtClient(orgID, ADMIN)
			ccPkg, err := gopackager.NewCCPackage(ccPath, d.getDeployPath(ccType))
			if err != nil {
				return err
			}

			installRqst := resmgmt.InstallCCRequest{Name: ccID, Path: ccPath, Version: "v1", Package: ccPkg}
			_, err = resMgmtClient.InstallCC(installRqst, resmgmt.WithRetry(resMgmtRetryOpts))
			if err != nil {
				return fmt.Errorf("SendInstallProposal return error: %s", err)
			}
		}

		sdkPeers = append(sdkPeers, sdkPeer)
	}

	argsArray := strings.Split(args, ",")

	var collConfig []*pb.CollectionConfig
	if collectionNames != "" {
		// Define the private data collection policy config
		for _, collName := range strings.Split(collectionNames, ",") {
			logger.Infof("Configuring collection (%s) for CCID=%s", collName, ccID)
			c, err := d.newCollectionConfig(channelID, collName)
			if err != nil {
				return err
			}
			collConfig = append(collConfig, c)
		}
	}

	resMgmtClient := d.BDDContext.ResMgmtClient(orgID, ADMIN)

	instantiateRqst := resmgmt.InstantiateCCRequest{Name: ccID, Path: ccPath, Version: "v1", Args: GetByteArgs(argsArray), Policy: chaincodePolicy,
		CollConfig: collConfig}

	_, err = resMgmtClient.InstantiateCC(
		channelID, instantiateRqst,
		resmgmt.WithTargets(sdkPeers...),
		resmgmt.WithTimeout(fabApi.Execute, 5*time.Minute),
		resmgmt.WithRetry(resMgmtRetryOpts),
	)
	return err
}

func (d *CommonSteps) newChaincodePolicy(ccPolicy, channelID string) (*fabricCommon.SignaturePolicyEnvelope, error) {
	return NewChaincodePolicy(d.BDDContext, ccPolicy, channelID)
}

//OrgPeers return array of PeerConfig
func (d *CommonSteps) OrgPeers(orgIDs, channelID string) Peers {
	var orgMap map[string]bool
	if orgIDs != "" {
		orgMap = make(map[string]bool)
		for _, orgID := range strings.Split(orgIDs, ",") {
			orgMap[orgID] = true
		}
	}
	var peers []*PeerConfig
	for _, pconfig := range d.BDDContext.PeersByChannel(channelID) {
		if orgMap == nil || orgMap[pconfig.OrgID] {
			peers = append(peers, pconfig)
		}
	}
	return peers
}

// Peers returns the PeerConfigs for the given peer IDs
func (d *CommonSteps) Peers(peerIDs string) (Peers, error) {
	var peers []*PeerConfig
	for _, id := range strings.Split(peerIDs, ",") {
		peer := d.BDDContext.PeerConfigForID(id)
		if peer == nil {
			return nil, errors.Errorf("peer [%s] not found", id)
		}
		peers = append(peers, peer)
	}
	return peers, nil
}

func (d *CommonSteps) warmUpCC(ccID, channelID string) error {
	logger.Infof("Warming up chaincode [%s] on channel [%s]", ccID, channelID)
	return d.warmUpCConOrg(ccID, "", channelID)
}

func (d *CommonSteps) warmUpCConOrg(ccID, orgIDs, channelID string) error {
	logger.Infof("Warming up chaincode [%s] on orgs [%s] and channel [%s]", ccID, orgIDs, channelID)
	for {
		_, err := d.QueryCCWithOpts(false, ccID, channelID, "", []string{"warmup"}, 5*time.Minute, false, 0, nil, d.OrgPeers(orgIDs, channelID)...)
		if err != nil && strings.Contains(err.Error(), "premature execution - chaincode") {
			// Wait until we can successfully invoke the chaincode
			logger.Infof("Error warming up chaincode [%s]: %s. Retrying in 5 seconds...", ccID, err)
			time.Sleep(5 * time.Second)
		} else {
			// Don't worry about any other type of error
			return nil
		}
	}
}

func (d *CommonSteps) defineCollectionConfig(id, collection, policy string, requiredPeerCount int, maxPeerCount int, blocksToLive int) error {
	logger.Infof("Defining collection config [%s] for collection [%s] - policy=[%s], requiredPeerCount=[%d], maxPeerCount=[%d], blocksToLive=[%d]", id, collection, policy, requiredPeerCount, maxPeerCount, blocksToLive)
	d.DefineCollectionConfig(id, collection, policy, int32(requiredPeerCount), int32(maxPeerCount), uint64(blocksToLive))
	return nil
}

func (d *CommonSteps) newCollectionConfig(channelID string, collName string) (*pb.CollectionConfig, error) {
	createCollectionConfig := d.BDDContext.CollectionConfig(collName)
	if createCollectionConfig == nil {
		return nil, errors.Errorf("no collection config defined for collection [%s]", collName)
	}
	return createCollectionConfig(channelID)
}

// DefineCollectionConfig defines a new private data collection configuration
func (d *CommonSteps) DefineCollectionConfig(id, name, policy string, requiredPeerCount, maxPeerCount int32, blocksToLive uint64) {
	d.BDDContext.DefineCollectionConfig(id,
		func(channelID string) (*pb.CollectionConfig, error) {
			sigPolicy, err := d.newChaincodePolicy(policy, channelID)
			if err != nil {
				return nil, errors.Wrapf(err, "error creating collection policy for collection [%s]", name)
			}
			return newPrivateCollectionConfig(name, requiredPeerCount, maxPeerCount, blocksToLive, sigPolicy), nil
		},
	)
}

func (d *CommonSteps) httpGetWithExpectedCode(url string, expectingCode int) error {
	_, code, _, err := HTTPGet(url)
	if err != nil {
		return err
	}

	if code != expectingCode {
		return errors.Errorf("expecting status code %d but got %d", expectingCode, code)
	}

	logger.Infof("Returned status code is %d which is the expected status code", code)

	return nil
}

func (d *CommonSteps) httpGet(url string) error {
	_, code, _, err := HTTPGet(url)
	if err != nil {
		return err
	}

	if code != http.StatusOK {
		return errors.Errorf("received status code %d", code)
	}

	return nil
}

func (d *CommonSteps) httpPostFile(url, path string) error {
	_, code, _, err := HTTPPostFile(url, path)
	if err != nil {
		return err
	}

	if code != http.StatusOK {
		return errors.Errorf("received status code %d", code)
	}

	return nil
}

func (d *CommonSteps) httpPostFileWithExpectedCode(url, path string, expectingCode int) error {
	_, code, _, err := HTTPPostFile(url, path)
	if err != nil {
		return err
	}

	if code != expectingCode {
		return errors.Errorf("expecting status code %d but got %d", expectingCode, code)
	}

	logger.Infof("Returned status code is %d which is the expected status code", code)

	return nil
}

func (d *CommonSteps) httpPost(url, data, contentType string) error {
	resolved, err := ResolveVars(data)
	if err != nil {
		return err
	}

	data = resolved.(string)

	_, code, _, err := HTTPPost(url, []byte(data), contentType)
	if err != nil {
		return err
	}

	if code != http.StatusOK {
		return errors.Errorf("received status code %d", code)
	}

	return nil
}

func (d *CommonSteps) httpPostWithExpectedCode(url, data, contentType string, expectingCode int) error {
	resolved, err := ResolveVars(data)
	if err != nil {
		return err
	}

	data = resolved.(string)

	_, code, _, err := HTTPPost(url, []byte(data), contentType)
	if err != nil {
		return err
	}

	if code != expectingCode {
		return errors.Errorf("expecting status code %d but got %d", expectingCode, code)
	}

	logger.Infof("Returned status code is %d which is the expected status code", code)

	return nil
}

// SetAuthTokenHeader sets the bearer token in the Authorization header if one
// is defined for the given request path.
func SetAuthTokenHeader(req *http.Request) {
	logger.Debugf("Looking for authorization token for URL [%s]", req.URL.Path)

	authToken := ""
	parts := strings.Split(req.URL.Path, "/")

	for i := len(parts); i > 1; i-- {
		basePath := strings.Join(parts[0:i], "/")
		logger.Debugf("... resolving authorization token for path [%s]", basePath)

		authToken = GetAuthToken(basePath, req.Method)
		if authToken != "" {
			break
		}
	}

	if authToken == "" {
		logger.Infof("Could not find bearer token for path [%s]", req.URL.Path)
		return
	}

	logger.Infof("Setting authorization header for bearer token [%s] for path [%s]", authToken, req.URL.Path)

	req.Header.Set(authHeader, tokenPrefix+authToken)
}

func (d *CommonSteps) decodeValueFromBase64(value, varName string) error {
	if err := ResolveVarsInExpression(&value); err != nil {
		return err
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return errors.Errorf("value [%s] is not a base64-encoded string: %s", value, err)
	}

	SetVar(varName, string(decodedBytes))

	logger.Infof("Decoded the base64-encoded value [%s] to [%s] and saved to variable [%s]", value, decodedBytes, varName)

	return nil
}

func (d *CommonSteps) convertValueToBase64URLEncoding(value, varName string) error {
	if err := ResolveVarsInExpression(&value); err != nil {
		return err
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return errors.Errorf("value [%s] is not a base64-encoded string: %s", value, err)
	}

	urlEncodedString := base64.URLEncoding.EncodeToString(decodedBytes)

	SetVar(varName, urlEncodedString)

	logger.Infof("Converted the base64-encoded value [%s] to base64URL-encoding [%s] and saved to variable [%s]", value, urlEncodedString, varName)

	return nil
}

func (d *CommonSteps) valuesEqual(value1, value2 string) error {
	if err := ResolveVarsInExpression(&value1, &value2); err != nil {
		return err
	}

	if value1 == value2 {
		logger.Infof("Values are equal [%s]", value1)

		return nil
	}

	logger.Infof("Value1 [%s] does not equal value 2 [%s]", value1, value2)

	return errors.Errorf("values [%s] and [%s] are not equal", value1, value2)
}

func (d *CommonSteps) setVariable(varName, value string) error {
	if err := ResolveVarsInExpression(&value); err != nil {
		return err
	}

	logger.Infof("Setting var [%s] to [%s]", varName, value)

	SetVar(varName, value)

	return nil
}

func (d *CommonSteps) setAuthTokenForPath(method, path, token string) error {
	if err := ResolveVarsInExpression(&method, &path, &token); err != nil {
		return err
	}

	logger.Infof("Setting authorization bearer token for [%s] (%s) to [%s]", path, method, token)

	SetAuthToken(path, method, token)

	return nil
}

func (d *CommonSteps) getOrgPeers(orgIDs, channelID string) ([]fabApi.Peer, string, error) {
	peers := d.OrgPeers(orgIDs, channelID)
	if len(peers) == 0 {
		return nil, "", errors.Errorf("no peers found for orgs [%s]", orgIDs)
	}

	var orgID string
	peersByOrg := make(map[string]fabApi.Peer)

	for _, pconfig := range peers {
		orgID = pconfig.OrgID

		if _, ok := peersByOrg[orgID]; ok {
			continue
		}

		sdkPeer, err := d.BDDContext.OrgUserContext(orgID, ADMIN).InfraProvider().CreatePeerFromConfig(&fabApi.NetworkPeer{PeerConfig: pconfig.Config})
		if err != nil {
			return nil, "", errors.WithMessage(err, "NewPeer failed")
		}

		peersByOrg[orgID] = sdkPeer
	}

	var sdkPeers []fabApi.Peer
	for _, p := range peersByOrg {
		sdkPeers = append(sdkPeers, p)
	}

	return sdkPeers, orgID, nil
}

func (d *CommonSteps) getCollectionConfig(channelID, ccID, collectionNames string) ([]*pb.CollectionConfig, error) {
	var collConfig []*pb.CollectionConfig
	if collectionNames != "" {
		// Define the private data collection policy config
		for _, collName := range strings.Split(collectionNames, ",") {
			logger.Infof("Configuring collection (%s) for CCID=%s", collName, ccID)
			c, err := d.newCollectionConfig(channelID, collName)
			if err != nil {
				return nil, err
			}
			collConfig = append(collConfig, c)
		}
	}

	return collConfig, nil
}

// SetAuthToken sets the authorization bearer token for the given HTTP path and HTTP method
func SetAuthToken(path HTTPPath, method HTTPMethod, token AuthToken) {
	tokensForPath, ok := authTokenMap[path]
	if !ok {
		tokensForPath = make(map[HTTPMethod]AuthToken)
		authTokenMap[path] = tokensForPath
	}

	tokensForPath[method] = token
}

// GetAuthToken returns the authorization bearer token for the given HTTP path and HTTP method
func GetAuthToken(path HTTPPath, method HTTPMethod) AuthToken {
	return authTokenMap[path][method]
}

// ClearState clears all global variables
func ClearState() {
	queryValue = ""
	vars = make(map[string]string)
	authTokenMap = make(map[HTTPPath]map[HTTPMethod]AuthToken)
}

// ClearResponse clears the query response
func ClearResponse() {
	queryValue = ""
}

// GetResponse returns the most recent query response
func GetResponse() string {
	return queryValue
}

// SetResponse sets the query response
func SetResponse(response string) {
	queryValue = response
}

// SetVar sets the value for the given variable
func SetVar(varName, value string) {
	vars[varName] = value
}

// GetVar gets the value for the given variable
// Returns true if the variable exists; false otherwise
func GetVar(varName string) (string, bool) {
	value, ok := vars[varName]
	return value, ok
}

// ResolveAllVars returns a slice of strings from the given comma-separated string.
// Each string is resolved for variables.
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
func ResolveAllVars(args string) ([]string, error) {
	return ResolveAll(vars, strings.Split(args, ","))
}

func newPrivateCollectionConfig(collName string, requiredPeerCount, maxPeerCount int32, blocksToLive uint64, policy *common.SignaturePolicyEnvelope) *pb.CollectionConfig {
	return &pb.CollectionConfig{
		Payload: &pb.CollectionConfig_StaticCollectionConfig{
			StaticCollectionConfig: &pb.StaticCollectionConfig{
				Name:              collName,
				RequiredPeerCount: requiredPeerCount,
				MaximumPeerCount:  maxPeerCount,
				BlockToLive:       blocksToLive,
				MemberOrgsPolicy: &pb.CollectionPolicyConfig{
					Payload: &pb.CollectionPolicyConfig_SignaturePolicy{
						SignaturePolicy: policy,
					},
				},
			},
		},
	}
}

// NewChaincodePolicy parses the policy string and returns the chaincode policy
func NewChaincodePolicy(bddCtx *BDDContext, ccPolicy, channelID string) (*fabricCommon.SignaturePolicyEnvelope, error) {
	if ccPolicy != "" {
		// Create a signature policy from the policy expression passed in
		return newPolicy(ccPolicy)
	}

	netwkConfig := bddCtx.clientConfig.NetworkConfig()

	// Default policy is 'signed by any member' for all known orgs
	var mspIDs []string
	for _, orgID := range bddCtx.OrgsByChannel(channelID) {
		orgConfig, ok := netwkConfig.Organizations[strings.ToLower(orgID)]
		if !ok {
			return nil, errors.Errorf("org config not found for org ID %s", orgID)
		}
		mspIDs = append(mspIDs, orgConfig.MSPID)
	}
	logger.Infof("Returning SignedByAnyMember policy for MSPs %s", mspIDs)
	return policydsl.SignedByAnyMember(mspIDs), nil
}

func contentTypeFromFileName(fileName string) (string, error) {
	p := strings.LastIndex(fileName, ".")
	if p == -1 {
		return "", errors.New("content type cannot be deduced since no file extension provided")
	}

	contentType := mime.TypeByExtension(fileName[p:])
	if contentType == "" {
		return "", errors.New("content type cannot be deduced from extension")
	}

	return contentType, nil
}

// HTTPGet sends a GET request to the given URL
func HTTPGet(url string) ([]byte, int, http.Header, error) {
	ClearResponse()

	client := &HTTPClient{}

	payload, statusCode, header, err := client.Get(url)
	if err != nil {
		return nil, 0, nil, err
	}

	PrintResponse(statusCode, payload, header)

	SetResponse(string(payload))

	return payload, statusCode, header, nil
}

// HTTPPost posts the given data to the given URL
func HTTPPost(url string, content []byte, contentType string) ([]byte, int, http.Header, error) {
	ClearResponse()

	client := &HTTPClient{}

	payload, statusCode, header, err := client.Post(url, content, contentType)
	if err != nil {
		return nil, 0, nil, err
	}

	PrintResponse(statusCode, payload, header)

	SetResponse(string(payload))

	return payload, statusCode, header, nil
}

func PrintResponse(statusCode int, payload []byte, header http.Header) {
	respContentType, ok := header["Content-Type"]
	if ok {
		switch {
		case strings.HasPrefix(respContentType[0], "image/"):
			logger.Infof("Received status code %d and an image of type [%s]", statusCode, respContentType[0])
		case strings.HasPrefix(respContentType[0], "text/"):
			logger.Infof("Received status code %d and a text response: [%s]", statusCode, payload)
		default:
			logger.Infof("Received status code %d and a response of type [%s]:\n%s", statusCode, respContentType[0], payload)
		}
	} else {
		logger.Infof("Received status code %d and a response with no Content-Type:\n%s", statusCode, payload)
	}
}

// HTTPPostFile posts the contents of the given file to the given URL
func HTTPPostFile(url, path string) ([]byte, int, http.Header, error) {
	logger.Infof("Uploading file [%s] to [%s]", path, url)

	contentType, err := contentTypeFromFileName(path)
	if err != nil {
		return nil, 0, nil, err
	}

	contents, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, 0, nil, err
	}

	return HTTPPost(url, contents, contentType)
}

// RegisterSteps register steps
func (d *CommonSteps) RegisterSteps(s *godog.Suite) {
	s.BeforeScenario(d.BDDContext.BeforeScenario)
	s.AfterScenario(d.BDDContext.AfterScenario)

	s.Step(`^the channel "([^"]*)" is created and all peers have joined$`, d.createChannelAndJoinAllPeers)
	s.Step(`^the channel "([^"]*)" is created and all peers from org "([^"]*)" have joined$`, d.createChannelAndJoinPeersFromOrg)
	s.Step(`^we wait (\d+) seconds$`, d.wait)
	s.Step(`^client queries chaincode "([^"]*)" with args "([^"]*)" on all peers in the "([^"]*)" org on the "([^"]*)" channel$`, d.queryCConOrg)
	s.Step(`^client queries chaincode "([^"]*)" with args "([^"]*)" on a single peer in the "([^"]*)" org on the "([^"]*)" channel$`, d.queryCConSinglePeerInOrg)
	s.Step(`^"([^"]*)" client queries chaincode "([^"]*)" with args "([^"]*)" on a single peer in the "([^"]*)" org on the "([^"]*)" channel$`, d.orgClientQueriesCConSinglePeerInOrg)
	s.Step(`^client queries chaincode "([^"]*)" with args "([^"]*)" on peers "([^"]*)" on the "([^"]*)" channel$`, d.queryCConTargetPeers)
	s.Step(`^client queries system chaincode "([^"]*)" with args "([^"]*)" on org "([^"]*)" peer on the "([^"]*)" channel$`, d.querySystemCC)
	s.Step(`^client queries system chaincode "([^"]*)" with args "([^"]*)" on org "([^"]*)" peer on the "([^"]*)" channel then the error response should contain "([^"]*)"$`, d.querySystemCCWithError)
	s.Step(`^client queries chaincode "([^"]*)" with args "([^"]*)" on the "([^"]*)" channel$`, d.queryCC)
	s.Step(`^client queries chaincode "([^"]*)" with args "([^"]*)" on the "([^"]*)" channel then the error response should contain "([^"]*)"$`, d.queryCCWithError)
	s.Step(`^response from "([^"]*)" to client contains value "([^"]*)"$`, d.containsInQueryValue)
	s.Step(`^response from "([^"]*)" to client equal value "([^"]*)"$`, d.equalQueryValue)
	s.Step(`^"([^"]*)" chaincode "([^"]*)" version "([^"]*)" is installed from path "([^"]*)" to all peers$`, d.installChaincodeToAllPeersWithVersion)
	s.Step(`^"([^"]*)" chaincode "([^"]*)" is installed from path "([^"]*)" to all peers$`, d.installChaincodeToAllPeers)
	s.Step(`^"([^"]*)" chaincode "([^"]*)" is installed from path "([^"]*)" to all peers in the "([^"]*)" org$`, d.installChaincodeToOrg)
	s.Step(`^"([^"]*)" chaincode "([^"]*)" is installed from path "([^"]*)" to all peers except "([^"]*)"$`, d.installChaincodeToAllPeersExcept)
	s.Step(`^"([^"]*)" chaincode "([^"]*)" is instantiated from path "([^"]*)" on all peers in the "([^"]*)" org on the "([^"]*)" channel with args "([^"]*)" with endorsement policy "([^"]*)" with collection policy "([^"]*)"$`, d.instantiateChaincodeOnOrg)
	s.Step(`^"([^"]*)" chaincode "([^"]*)" is instantiated from path "([^"]*)" on the "([^"]*)" channel with args "([^"]*)" with endorsement policy "([^"]*)" with collection policy "([^"]*)"$`, d.instantiateChaincode)
	s.Step(`^"([^"]*)" chaincode "([^"]*)" is upgraded with version "([^"]*)" from path "([^"]*)" on the "([^"]*)" channel with args "([^"]*)" with endorsement policy "([^"]*)" with collection policy "([^"]*)"$`, d.upgradeChaincode)
	s.Step(`^"([^"]*)" chaincode "([^"]*)" is upgraded with version "([^"]*)" from path "([^"]*)" on the "([^"]*)" channel with args "([^"]*)" with endorsement policy "([^"]*)" with collection policy "([^"]*)" then the error response should contain "([^"]*)"$`, d.upgradeChaincodeWithError)
	s.Step(`^"([^"]*)" chaincode "([^"]*)" is deployed from path "([^"]*)" to all peers in the "([^"]*)" org on the "([^"]*)" channel with args "([^"]*)" with endorsement policy "([^"]*)" with collection policy "([^"]*)"$`, d.deployChaincodeToOrg)
	s.Step(`^"([^"]*)" chaincode "([^"]*)" is deployed from path "([^"]*)" to all peers on the "([^"]*)" channel with args "([^"]*)" with endorsement policy "([^"]*)" with collection policy "([^"]*)"$`, d.deployChaincode)
	s.Step(`^chaincode "([^"]*)" is warmed up on all peers in the "([^"]*)" org on the "([^"]*)" channel$`, d.warmUpCConOrg)
	s.Step(`^chaincode "([^"]*)" is warmed up on all peers on the "([^"]*)" channel$`, d.warmUpCC)
	s.Step(`^client invokes chaincode "([^"]*)" with args "([^"]*)" on all peers in the "([^"]*)" org on the "([^"]*)" channel$`, d.InvokeCConOrg)
	s.Step(`^client invokes chaincode "([^"]*)" with args "([^"]*)" on the "([^"]*)" channel$`, d.InvokeCC)
	s.Step(`^"([^"]*)" client invokes chaincode "([^"]*)" with args "([^"]*)" on the "([^"]*)" channel$`, d.orgClientInvokesCC)
	s.Step(`^"([^"]*)" client invokes chaincode "([^"]*)" with args "([^"]*)" on the "([^"]*)" channel then the error response should contain "([^"]*)"$`, d.orgClientInvokesCCWithExpectedError)
	s.Step(`^client invokes chaincode "([^"]*)" with args "([^"]*)" on peers "([^"]*)" on the "([^"]*)" channel$`, d.invokeCConTargetPeers)
	s.Step(`^collection config "([^"]*)" is defined for collection "([^"]*)" as policy="([^"]*)", requiredPeerCount=(\d+), maxPeerCount=(\d+), and blocksToLive=(\d+)$`, d.defineCollectionConfig)
	s.Step(`^block (\d+) from the "([^"]*)" channel is displayed$`, d.displayBlockFromChannel)
	s.Step(`^the last (\d+) blocks from the "([^"]*)" channel are displayed$`, d.displayBlocksFromChannel)
	s.Step(`^the last block from the "([^"]*)" channel is displayed$`, d.displayLastBlockFromChannel)
	s.Step(`^the response is saved to variable "([^"]*)"$`, d.setVariableFromCCResponse)
	s.Step(`^variable "([^"]*)" is assigned the value "([^"]*)"$`, d.setVariable)
	s.Step(`^variable "([^"]*)" is assigned the JSON value '([^']*)'$`, d.setJSONVariable)
	s.Step(`^the response equals "([^"]*)"$`, d.responseEquals)
	s.Step(`^the JSON path "([^"]*)" of the response equals "([^"]*)"$`, d.jsonPathOfCCResponseEquals)
	s.Step(`^the JSON path "([^"]*)" of the numeric response equals "([^"]*)"$`, d.jsonPathOfNumericResponseEquals)
	s.Step(`^the JSON path "([^"]*)" of the boolean response equals "([^"]*)"$`, d.jsonPathOfBoolResponseEquals)
	s.Step(`^the JSON path "([^"]*)" of the response has (\d+) items$`, d.jsonPathOfCCHasNumItems)
	s.Step(`^the JSON path "([^"]*)" of the response contains "([^"]*)"$`, d.jsonPathOfCCResponseContains)
	s.Step(`^the JSON path "([^"]*)" of the response does not contain "([^"]*)"$`, d.jsonPathOfResponseNotContains)
	s.Step(`^the JSON path "([^"]*)" of the response is saved to variable "([^"]*)"$`, d.jsonPathOfResponseSavedToVar)
	s.Step(`^the JSON path "([^"]*)" of the numeric response is saved to variable "([^"]*)"$`, d.jsonPathOfNumericResponseSavedToVar)
	s.Step(`^the JSON path "([^"]*)" of the boolean response is saved to variable "([^"]*)"$`, d.jsonPathOfBoolResponseSavedToVar)
	s.Step(`^the JSON path "([^"]*)" of the raw response is saved to variable "([^"]*)"$`, d.jsonPathOfRawResponseSavedToVar)
	s.Step(`^the JSON path "([^"]*)" of the response is not empty$`, d.jsonPathOfResponseNotEmpty)
	s.Step(`^the JSON path "([^"]*)" of the array response is not empty$`, d.jsonPathOfArrayResponseNotEmpty)
	s.Step(`^an HTTP GET is sent to "([^"]*)"$`, d.httpGet)
	s.Step(`^an HTTP GET is sent to "([^"]*)" and the returned status code is (\d+)$`, d.httpGetWithExpectedCode)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content from file "([^"]*)"$`, d.httpPostFile)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content from file "([^"]*)" and the returned status code is (\d+)$`, d.httpPostFileWithExpectedCode)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content "([^"]*)" of type "([^"]*)"$`, d.httpPost)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content "([^"]*)" of type "([^"]*)" and the returned status code is (\d+)$`, d.httpPostWithExpectedCode)
	s.Step(`^the base64-encoded value "([^"]*)" is decoded and saved to variable "([^"]*)"$`, d.decodeValueFromBase64)
	s.Step(`^the base64-encoded value "([^"]*)" is converted to base64URL-encoding and saved to variable "([^"]*)"$`, d.convertValueToBase64URLEncoding)
	s.Step(`^the value "([^"]*)" equals "([^"]*)"$`, d.valuesEqual)
	s.Step(`^the authorization bearer token for "([^"]*)" requests to path "([^"]*)" is set to "([^"]*)"$`, d.setAuthTokenForPath)
	s.Step(`^chaincode "([^"]*)" is installed from path "([^"]*)" to all peers$`, d.lifecycleInstallCCToAllPeers)
	s.Step(`^chaincode "([^"]*)", version "([^"]*)", package ID "([^"]*)", sequence (\d+) is approved by orgs "([^"]*)" on the "([^"]*)" channel with endorsement policy "([^"]*)" and collection policy "([^"]*)"$`, d.approveCCByOrg)
	s.Step(`^chaincode "([^"]*)", version "([^"]*)", package ID "([^"]*)", sequence (\d+) is approved by orgs "([^"]*)" on the "([^"]*)" channel with endorsement policy "([^"]*)" and collection policy "([^"]*)" then the error response should contain "([^"]*)"$`, d.approveCCByOrgWithError)
	s.Step(`^chaincode "([^"]*)", version "([^"]*)", sequence (\d+) is committed by orgs "([^"]*)" on the "([^"]*)" channel with endorsement policy "([^"]*)" and collection policy "([^"]*)"$`, d.commitCCByOrg)
	s.Step(`^chaincode "([^"]*)", version "([^"]*)", sequence (\d+) is checked for readiness by orgs "([^"]*)" on the "([^"]*)" channel with endorsement policy "([^"]*)" and collection policy "([^"]*)"$`, d.checkCommitReadinessByOrg)
	s.Step(`^peer "([^"]*)" is queried for installed chaincodes$`, d.queryInstalledCC)
	s.Step(`^committed chaincode "([^"]*)" is queried by orgs "([^"]*)" on the "([^"]*)" channel$`, d.queryCommittedCCByOrg)
	s.Step(`^all committed chaincodes are queried by orgs "([^"]*)" on the "([^"]*)" channel$`, d.queryCommittedCCsByOrg)
	s.Step(`^peer "([^"]*)" is queried for approved chaincode "([^"]*)" and sequence (\d+) on the "([^"]*)" channel$`, d.queryApprovedCCByPeer)
	s.Step(`^peer "([^"]*)" is queried for installed chaincode package "([^"]*)"$`, d.queryInstalledCCPackage)
	s.Step(`^chaincode "([^"]*)", version "([^"]*)", package ID "([^"]*)", sequence (\d+) is approved and committed by orgs "([^"]*)" on the "([^"]*)" channel with endorsement policy "([^"]*)" and collection policy "([^"]*)"$`, d.approveAndCommitCCByOrg)
}
