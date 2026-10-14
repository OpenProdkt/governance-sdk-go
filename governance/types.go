package governance

import "time"

type EntitlementSet struct {
	Source         string          `json:"source"`
	Status         string          `json:"status"`
	Version        string          `json:"version"`
	OrganizationID string          `json:"organizationId"`
	TenantID       string          `json:"tenantId,omitempty"`
	DeploymentID   string          `json:"deploymentId,omitempty"`
	Modules        []string        `json:"modules"`
	Features       map[string]bool `json:"features"`
	Limits         map[string]int  `json:"limits"`
}

type BillingSnapshot struct {
	Provider          string     `json:"provider"`
	CustomerID        string     `json:"customerId,omitempty"`
	SubscriptionID    string     `json:"subscriptionId,omitempty"`
	PriceID           string     `json:"priceId,omitempty"`
	Status            string     `json:"status"`
	CurrentPeriodEnd  *time.Time `json:"currentPeriodEnd,omitempty"`
	CancelAtPeriodEnd bool       `json:"cancelAtPeriodEnd"`
	CanceledAt        *time.Time `json:"canceledAt,omitempty"`
	UpdatedAt         *time.Time `json:"updatedAt,omitempty"`
	GraceUntil        *time.Time `json:"graceUntil,omitempty"`
}

type DecisionRequest struct {
	AssetID  string                 `json:"asset_id,omitempty"`
	AssetKey string                 `json:"asset_key,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type AuthorizationRequest struct {
	AssetID          string
	AssetKey         string
	AssetIdentity    *AssetIdentity
	PrincipalContext *PrincipalContext
	OperationID      string
	ApprovalID       string
	PayloadHash      string
	Metadata         any
	Transport        *TransportContext
}

// ApprovalRetry is the stored approval tuple for an explicit retry of one approved operation.
type ApprovalRetry struct {
	ApprovalID  string
	PayloadHash string
}

// PrincipalContext carries an adapter-verified bearer credential. It is used
// only in the Authorization header and is never serialized into EvaluateRequest.
type PrincipalContext struct {
	BearerToken string
}

type EvaluateAsset struct {
	ID          string `json:"id,omitempty"`
	Key         string `json:"key,omitempty"`
	Application string `json:"application,omitempty"`
	Service     string `json:"service,omitempty"`
	Environment string `json:"environment,omitempty"`
}

type HTTPTransport struct {
	Method  string            `json:"method,omitempty"`
	Path    string            `json:"path,omitempty"`
	Host    string            `json:"host,omitempty"`
	Scheme  string            `json:"scheme,omitempty"`
	RouteID string            `json:"route_id,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type GRPCTransport struct {
	FullMethod string            `json:"full_method,omitempty"`
	Service    string            `json:"service,omitempty"`
	Method     string            `json:"method,omitempty"`
	RPCType    string            `json:"rpc_type,omitempty"`
	RouteID    string            `json:"route_id,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type MCPTransport struct {
	Operation string                 `json:"operation,omitempty"`
	Server    string                 `json:"server,omitempty"`
	Tool      string                 `json:"tool,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
	SessionID string                 `json:"session_id,omitempty"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type TransportContext struct {
	Kind string         `json:"kind"`
	HTTP *HTTPTransport `json:"http,omitempty"`
	GRPC *GRPCTransport `json:"grpc,omitempty"`
	MCP  *MCPTransport  `json:"mcp,omitempty"`
}

type EvaluateRequest struct {
	Version     string                 `json:"version"`
	Asset       EvaluateAsset          `json:"asset"`
	OperationID string                 `json:"operation_id"`
	ApprovalID  string                 `json:"approval_id,omitempty"`
	PayloadHash string                 `json:"payload_hash,omitempty"`
	Transport   TransportContext       `json:"transport"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type DecisionResponse struct {
	Version           string     `json:"version,omitempty"`
	OperationID       string     `json:"operation_id,omitempty"`
	OrganizationID    string     `json:"organizationId,omitempty"`
	AssetID           string     `json:"assetId,omitempty"`
	AssetKey          string     `json:"assetKey,omitempty"`
	Decision          string     `json:"decision"`
	DecisionID        string     `json:"decisionId"`
	Reason            string     `json:"reason,omitempty"`
	PolicyID          string     `json:"policyId,omitempty"`
	Code              string     `json:"code,omitempty"`
	Error             string     `json:"error,omitempty"`
	ApprovalID        string     `json:"approvalId,omitempty"`
	PayloadHash       string     `json:"payload_hash,omitempty"`
	ApprovalStatus    string     `json:"approvalStatus,omitempty"`
	ApprovalExpiresAt *time.Time `json:"approval_expires_at,omitempty"`
	GrantExpiresAt    *time.Time `json:"grant_expires_at,omitempty"`
}

type RequestCodeRequest struct {
	Email string `json:"email"`
}

type VerifyCodeRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type VerifyCodeResponse struct {
	AccessToken string    `json:"accessToken"`
	TokenType   string    `json:"tokenType"`
	ExpiresAt   time.Time `json:"expiresAt"`
	UserID      string    `json:"userId"`
}

type RegisterRequest struct {
	OrganizationName string `json:"organizationName"`
	Email            string `json:"email"`
}

type BootstrapRequest struct {
	OrganizationName string `json:"organizationName"`
	OwnerEmail       string `json:"ownerEmail"`
	Tier             string `json:"tier"`
	Mode             string `json:"mode"`
}

type InviteMemberRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type CreateAPIKeyRequest struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

type CreateAssetRequest struct {
	Name          string                 `json:"name"`
	AssetKey      string                 `json:"assetKey,omitempty"`
	Environment   string                 `json:"environment"`
	Definition    map[string]interface{} `json:"definition,omitempty"`
	Group         string                 `json:"group"`
	OwnerUserID   string                 `json:"ownerUserId,omitempty"`
	PresetID      string                 `json:"presetId,omitempty"`
	PresetVersion string                 `json:"presetVersion,omitempty"`
}

type UpdateAssetRequest struct {
	Name          string                 `json:"name"`
	AssetKey      string                 `json:"assetKey,omitempty"`
	Environment   string                 `json:"environment"`
	Definition    map[string]interface{} `json:"definition,omitempty"`
	Group         string                 `json:"group"`
	OwnerUserID   string                 `json:"ownerUserId,omitempty"`
	PresetID      string                 `json:"presetId,omitempty"`
	PresetVersion string                 `json:"presetVersion,omitempty"`
}

type DiscoveredAsset struct {
	Key         string                 `json:"key"`
	DisplayName string                 `json:"displayName,omitempty"`
	Kind        string                 `json:"kind"`
	Environment string                 `json:"environment"`
	Identifiers map[string]interface{} `json:"identifiers,omitempty"`
}

type DiscoverySource struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
}

type DiscoveryEvidence struct {
	Kind       string                 `json:"kind"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

type IngestAssetDiscoveryRequest struct {
	DiscoveryID   string                 `json:"discovery_id"`
	SchemaVersion string                 `json:"schema_version,omitempty"`
	Asset         DiscoveredAsset        `json:"asset"`
	Metadata      map[string]interface{} `json:"metadata"`
	Source        DiscoverySource        `json:"source"`
	Evidence      DiscoveryEvidence      `json:"evidence"`
	ObservedAt    time.Time              `json:"observed_at"`
}

type AssetDiscovery struct {
	DiscoveryID    string                 `json:"discoveryId"`
	OrganizationID string                 `json:"organizationId"`
	SchemaVersion  string                 `json:"schemaVersion"`
	Asset          DiscoveredAsset        `json:"asset"`
	Metadata       map[string]interface{} `json:"metadata"`
	Source         DiscoverySource        `json:"source"`
	Evidence       DiscoveryEvidence      `json:"evidence"`
	ObservedAt     time.Time              `json:"observedAt"`
	ReceivedAt     time.Time              `json:"receivedAt"`
}

type AssetDiscoveriesResponse struct {
	OrganizationID string           `json:"organizationId"`
	Discoveries    []AssetDiscovery `json:"discoveries"`
}

type CreateGroupRequest struct {
	Name      string `json:"name"`
	Approvers string `json:"approvers"`
}

type UpdateGroupRequest struct {
	Approvers string `json:"approvers"`
}

type CreatePolicyRequest struct {
	AssetID   string                 `json:"assetId"`
	Name      string                 `json:"name"`
	Condition map[string]interface{} `json:"condition"`
	Decision  string                 `json:"decision"`
}

type ResolveApprovalRequest struct {
	Comment string `json:"comment,omitempty"`
}

type Policy struct {
	ID             string                 `json:"id"`
	OrganizationID string                 `json:"organizationId"`
	AssetID        string                 `json:"assetId"`
	Name           string                 `json:"name"`
	Condition      map[string]interface{} `json:"condition"`
	Decision       string                 `json:"decision"`
	IsActive       bool                   `json:"isActive"`
	CreatedAt      time.Time              `json:"createdAt"`
}

type PolicyRevision struct {
	Policy
	PolicyID string `json:"policyId"`
	Action   string `json:"action"`
}

type PolicyRevisionsResponse struct {
	OrganizationID string           `json:"organizationId"`
	PolicyID       string           `json:"policyId"`
	Revisions      []PolicyRevision `json:"revisions"`
}

type Approval struct {
	ID             string         `json:"id"`
	OrganizationID string         `json:"organizationId"`
	DecisionID     string         `json:"decisionId"`
	AssetID        string         `json:"assetId,omitempty"`
	PolicyID       string         `json:"policyId,omitempty"`
	RequesterID    string         `json:"requesterId,omitempty"`
	RequestContext map[string]any `json:"requestContext,omitempty"`
	Status         string         `json:"status"`
	CreatedAt      time.Time      `json:"createdAt"`
	ExpiresAt      time.Time      `json:"expiresAt"`
	ReviewedAt     *time.Time     `json:"reviewedAt,omitempty"`
	ReviewedBy     string         `json:"reviewedBy,omitempty"`
	Comment        string         `json:"comment,omitempty"`
	GrantExpiresAt *time.Time     `json:"grantExpiresAt,omitempty"`
	ConsumedAt     *time.Time     `json:"consumedAt,omitempty"`
	RevokedAt      *time.Time     `json:"revokedAt,omitempty"`
}

type ApprovalQuery struct {
	Status string
	Limit  int
	Offset int
}
type ApprovalPage struct {
	OrganizationID string         `json:"organizationId"`
	Approvals      []Approval     `json:"approvals"`
	Counts         map[string]int `json:"counts"`
	Total          int            `json:"total"`
	Limit          int            `json:"limit"`
	Offset         int            `json:"offset"`
}

type AuditQuery struct {
	EventType    string
	ActorID      string
	ResourceType string
	ResourceID   string
	Outcome      string
	Limit        int
	Offset       int
}

type AuditEvent struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	EventType      string    `json:"eventType"`
	ActorID        string    `json:"actorId,omitempty"`
	ResourceType   string    `json:"resourceType,omitempty"`
	ResourceID     string    `json:"resourceId,omitempty"`
	Outcome        string    `json:"outcome,omitempty"`
	Payload        string    `json:"payload"`
	CreatedAt      time.Time `json:"createdAt"`
}

type AuditPage struct {
	OrganizationID string       `json:"organizationId"`
	Events         []AuditEvent `json:"events"`
	Total          int          `json:"total"`
	Limit          int          `json:"limit"`
	Offset         int          `json:"offset"`
}

type DecisionExplorerItem struct {
	DecisionID       string                 `json:"decisionId"`
	OrganizationID   string                 `json:"organizationId"`
	PolicyID         string                 `json:"policyId,omitempty"`
	PolicyRevisionID string                 `json:"policyRevisionId,omitempty"`
	Asset            string                 `json:"asset"`
	Metadata         map[string]interface{} `json:"metadata"`
	Timestamp        time.Time              `json:"timestamp"`
	Decision         string                 `json:"decision"`
	Result           string                 `json:"result"`
	Status           string                 `json:"status"`
	ErrorCode        string                 `json:"errorCode,omitempty"`
	ErrorMessage     string                 `json:"errorMessage,omitempty"`
}

type DecisionExplorerResponse struct {
	OrganizationID string                 `json:"organizationId"`
	Items          []DecisionExplorerItem `json:"items"`
	Total          int                    `json:"total"`
	Limit          int                    `json:"limit"`
	Offset         int                    `json:"offset"`
}

type DecisionQuery struct {
	Decision string
	Status   string
	AssetID  string
	PolicyID string
	Search   string
	From     *time.Time
	To       *time.Time
	Limit    int
	Offset   int
}
