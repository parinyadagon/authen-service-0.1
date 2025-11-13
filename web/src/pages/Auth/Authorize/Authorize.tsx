import { useState, useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router";
import { Container, Paper, Text, Title, Button, Stack, Alert, Group, Badge, Card, Divider, List, ThemeIcon, Loader, Center } from "@mantine/core";
import { IconShield, IconUser, IconDevices, IconCheck, IconX, IconExternalLink } from "@tabler/icons-react";
import { useAuth } from "@/hooks/useAuth";

interface AuthorizeRequest {
  client_id: string;
  redirect_uri: string;
  response_type: string;
  scope?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
}

interface ClientInfo {
  name: string;
  description: string;
  logo?: string;
  website?: string;
  trusted: boolean;
}

// Fetch client info from backend API
const fetchClientInfo = async (clientId: string): Promise<ClientInfo | null> => {
  try {
    const response = await fetch(`http://localhost:8080/oauth/clients/${clientId}`);
    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    return {
      name: data.client_name || clientId,
      description: `OAuth2 client registered at ${new Date(data.created_at).toLocaleDateString()}`,
      website: data.redirect_uri?.split(",")[0] || undefined,
      trusted: data.client_name?.toLowerCase().includes("trusted") || false,
    };
  } catch (error) {
    console.error("Failed to fetch client info:", error);
    return null;
  }
};

// Fallback client registry for when backend is unavailable
const FALLBACK_CLIENT_REGISTRY: Record<string, ClientInfo> = {
  "test-client-1": {
    name: "Demo OAuth Client",
    description: "Test application for OAuth2 demonstration",
    website: "http://localhost:3000",
    trusted: false,
  },
  "trusted-app": {
    name: "Trusted Enterprise App",
    description: "Internal company application with full access",
    trusted: true,
  },
};

export function Authorize() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { user, isAuthenticated, loading: authLoading } = useAuth();

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authorizeRequest, setAuthorizeRequest] = useState<AuthorizeRequest | null>(null);
  const [clientInfo, setClientInfo] = useState<ClientInfo | null>(null);

  useEffect(() => {
    const loadClientInfo = async () => {
      // Parse OAuth2 parameters from URL
      const params: AuthorizeRequest = {
        client_id: searchParams.get("client_id") || "",
        redirect_uri: searchParams.get("redirect_uri") || "",
        response_type: searchParams.get("response_type") || "",
        scope: searchParams.get("scope") || undefined,
        state: searchParams.get("state") || undefined,
        code_challenge: searchParams.get("code_challenge") || undefined,
        code_challenge_method: searchParams.get("code_challenge_method") || undefined,
      };

      setAuthorizeRequest(params);

      // Validate required parameters
      if (!params.client_id || !params.redirect_uri || !params.response_type) {
        setError("Missing required OAuth2 parameters");
        return;
      }

      // Fetch client information from backend
      const clientInfo = await fetchClientInfo(params.client_id);

      if (clientInfo) {
        setClientInfo(clientInfo);
      } else {
        // Fallback to static registry
        const fallbackClient = FALLBACK_CLIENT_REGISTRY[params.client_id];
        setClientInfo(
          fallbackClient || {
            name: params.client_id,
            description: "Third-party application",
            trusted: false,
          }
        );
      }
    };

    loadClientInfo();
  }, [searchParams]);

  const handleApprove = async () => {
    if (!authorizeRequest || !user) return;

    try {
      setLoading(true);
      setError(null);

      // Build query parameters for the authorize endpoint
      const queryParams = new URLSearchParams({
        response_type: authorizeRequest.response_type,
        client_id: authorizeRequest.client_id,
        redirect_uri: authorizeRequest.redirect_uri,
        ...(authorizeRequest.scope && { scope: authorizeRequest.scope }),
        ...(authorizeRequest.state && { state: authorizeRequest.state }),
        ...(authorizeRequest.code_challenge && { code_challenge: authorizeRequest.code_challenge }),
        ...(authorizeRequest.code_challenge_method && { code_challenge_method: authorizeRequest.code_challenge_method }),
      });

      // Call backend authorize endpoint
      const response = await fetch(`http://localhost:8080/oauth/authorize?${queryParams.toString()}`, {
        method: "GET",
        headers: {
          "X-User-ID": user.user_id || user.id || "",
          "Content-Type": "application/json",
        },
        credentials: "include",
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.details || "Authorization failed");
      }

      const data = await response.json();

      if (data.data && data.data.code) {
        // Redirect back to client with authorization code
        const redirectUrl = new URL(authorizeRequest.redirect_uri);
        redirectUrl.searchParams.append("code", data.data.code);
        if (authorizeRequest.state) {
          redirectUrl.searchParams.append("state", authorizeRequest.state);
        }

        // Redirect to client application
        window.location.href = redirectUrl.toString();
      } else {
        throw new Error("No authorization code received");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authorization failed");
    } finally {
      setLoading(false);
    }
  };

  const handleDeny = () => {
    if (!authorizeRequest) return;

    // Redirect back to client with error
    const redirectUrl = new URL(authorizeRequest.redirect_uri);
    redirectUrl.searchParams.append("error", "access_denied");
    redirectUrl.searchParams.append("error_description", "User denied the request");
    if (authorizeRequest.state) {
      redirectUrl.searchParams.append("state", authorizeRequest.state);
    }

    window.location.href = redirectUrl.toString();
  };

  // Show loading while checking authentication
  if (authLoading) {
    return (
      <Container size="sm" my={40}>
        <Center h={200}>
          <Loader size="lg" />
        </Center>
      </Container>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    const loginUrl = `/login?redirect=${encodeURIComponent(window.location.pathname + window.location.search)}`;
    navigate(loginUrl, { replace: true });
    return null;
  }

  // Show error if parameters are invalid
  if (error && !authorizeRequest) {
    return (
      <Container size="sm" my={40}>
        <Alert color="red" title="Invalid Authorization Request">
          {error}
        </Alert>
      </Container>
    );
  }

  if (!authorizeRequest) {
    return (
      <Container size="sm" my={40}>
        <Center h={200}>
          <Loader size="lg" />
        </Center>
      </Container>
    );
  }

  const scopes = authorizeRequest.scope ? authorizeRequest.scope.split(" ") : [];
  const isSecureFlow = authorizeRequest.code_challenge && authorizeRequest.code_challenge_method;

  return (
    <Container size="sm" my={40}>
      <Paper withBorder shadow="sm" p={30} radius="md">
        {/* Header */}
        <Stack gap="md" align="center" mb="xl">
          <ThemeIcon size={60} radius="xl" color="blue">
            <IconShield size={30} />
          </ThemeIcon>
          <Title order={2} ta="center">
            Authorization Request
          </Title>
          <Text size="sm" c="dimmed" ta="center">
            An application is requesting access to your account
          </Text>
        </Stack>

        {error && (
          <Alert color="red" mb="md">
            {error}
          </Alert>
        )}

        {/* Client Information */}
        <Card withBorder mb="md">
          <Group justify="space-between" mb="md">
            <div>
              <Text fw={500} size="lg">
                {clientInfo?.name || authorizeRequest.client_id}
              </Text>
              <Text size="sm" c="dimmed">
                {clientInfo?.description || "Third-party application"}
              </Text>
            </div>
            {clientInfo?.trusted && (
              <Badge color="green" variant="light">
                Trusted
              </Badge>
            )}
          </Group>

          {clientInfo?.website && (
            <Group gap="xs" mb="md">
              <IconExternalLink size={16} />
              <Text size="sm" c="blue" component="a" href={clientInfo.website} target="_blank">
                {clientInfo.website}
              </Text>
            </Group>
          )}

          <Divider mb="md" />

          {/* User Information */}
          <Group gap="sm" mb="md">
            <IconUser size={16} />
            <div>
              <Text size="sm" fw={500}>
                Authorizing as: {user?.username || user?.first_name || "User"}
              </Text>
              <Text size="xs" c="dimmed">
                {user?.email || `ID: ${user?.user_id || user?.id}`}
              </Text>
            </div>
          </Group>
        </Card>

        {/* Permissions Requested */}
        <Card withBorder mb="md">
          <Text fw={500} mb="md">
            This application will be able to:
          </Text>
          <List
            spacing="xs"
            size="sm"
            icon={
              <ThemeIcon color="blue" size={18} radius="xl">
                <IconCheck size={12} />
              </ThemeIcon>
            }>
            {scopes.length > 0 ? (
              scopes.map((scope, index) => <List.Item key={index}>{getScopeDescription(scope)}</List.Item>)
            ) : (
              <List.Item>Access your basic profile information</List.Item>
            )}
            <List.Item>Identify you in their system</List.Item>
            {authorizeRequest.response_type === "code" && <List.Item>Receive an authorization code for secure access</List.Item>}
          </List>
        </Card>

        {/* Security Information */}
        <Card withBorder mb="xl" bg="gray.0">
          <Group gap="sm" mb="xs">
            <IconDevices size={16} />
            <Text size="sm" fw={500}>
              Security Information
            </Text>
          </Group>
          <Stack gap="xs">
            <Group justify="space-between">
              <Text size="xs" c="dimmed">
                Flow Type:
              </Text>
              <Badge size="xs" color={isSecureFlow ? "green" : "orange"}>
                {isSecureFlow ? "PKCE (Secure)" : "Standard"}
              </Badge>
            </Group>
            <Group justify="space-between">
              <Text size="xs" c="dimmed">
                Response Type:
              </Text>
              <Text size="xs" ff="monospace">
                {authorizeRequest.response_type}
              </Text>
            </Group>
            <Group justify="space-between">
              <Text size="xs" c="dimmed">
                Client ID:
              </Text>
              <Text size="xs" ff="monospace">
                {authorizeRequest.client_id}
              </Text>
            </Group>
            {authorizeRequest.state && (
              <Group justify="space-between">
                <Text size="xs" c="dimmed">
                  State:
                </Text>
                <Text size="xs" ff="monospace">
                  {authorizeRequest.state.substring(0, 10)}...
                </Text>
              </Group>
            )}
          </Stack>
        </Card>

        {/* Action Buttons */}
        <Group justify="space-between">
          <Button variant="subtle" color="red" leftSection={<IconX size={18} />} onClick={handleDeny} disabled={loading}>
            Deny
          </Button>
          <Button leftSection={<IconCheck size={18} />} onClick={handleApprove} loading={loading} disabled={loading}>
            {loading ? "Authorizing..." : "Authorize"}
          </Button>
        </Group>

        {/* Footer */}
        <Text size="xs" c="dimmed" ta="center" mt="xl">
          By authorizing, you allow this application to access your account according to their terms of service. You can revoke this access at any
          time from your account settings.
        </Text>
      </Paper>
    </Container>
  );
}

// Helper function to convert OAuth2 scopes to human-readable descriptions
function getScopeDescription(scope: string): string {
  const scopeDescriptions: Record<string, string> = {
    read: "Read your profile information",
    write: "Modify your profile information",
    email: "Access your email address",
    profile: "Access your basic profile information",
    openid: "Verify your identity",
    offline_access: "Access your account when you're not online",
  };

  return scopeDescriptions[scope] || `Access ${scope} information`;
}
