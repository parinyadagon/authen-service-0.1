import { useState, useEffect } from "react";
import {
  Container,
  Paper,
  Text,
  Title,
  Group,
  Button,
  Badge,
  Stack,
  Alert,
  Card,
  Grid,
  Avatar,
  ActionIcon,
  Tooltip,
  Divider,
  Tabs,
  Table,
  Loader,
  Center,
} from "@mantine/core";
import {
  IconUser,
  IconLogout,
  IconShield,
  IconDevices,
  IconRefresh,
  IconTrash,
  IconEye,
  IconSettings,
  IconMail,
  IconCalendar,
} from "@tabler/icons-react";
import { AuthService } from "../../services/auth.service";
import type { UserProfile, SessionInfo } from "../../types/auth.types";
import { useNavigate } from "react-router";

export function Profile() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [user, setUser] = useState<UserProfile | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [logoutLoading, setLogoutLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<string>("profile");
  const [sessionsLoading, setSessionsLoading] = useState(false);

  const navigate = useNavigate();

  useEffect(() => {
    loadProfile();
  }, []);

  useEffect(() => {
    if (activeTab === "sessions") {
      loadSessions();
    }
  }, [activeTab]);

  const loadProfile = async () => {
    try {
      setLoading(true);
      setError(null);

      // Skip auth check since ProtectedRoute already handles it
      // Just load profile data directly
      const profile = await AuthService.getProfile();
      setUser(profile);
      console.log("👤 Profile loaded:", profile);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load profile");
      console.error("❌ Profile load error:", err);
    } finally {
      setLoading(false);
    }
  };

  const loadSessions = async () => {
    try {
      setSessionsLoading(true);

      try {
        const sessionList = await AuthService.getSessions();
        setSessions(sessionList);
        console.log("📊 Sessions loaded:", sessionList);
      } catch {
        // If sessions API fails, just set empty array
        setSessions([]);
      }
    } catch (err) {
      console.error("❌ Failed to load sessions:", err);
      setSessions([]);
    } finally {
      setSessionsLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      setLogoutLoading(true);
      await AuthService.logout();
      navigate("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Logout failed");
    } finally {
      setLogoutLoading(false);
    }
  };

  const handleRevokeAll = async () => {
    try {
      setLogoutLoading(true);
      await AuthService.revokeAllSessions();
      navigate("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke sessions");
    } finally {
      setLogoutLoading(false);
    }
  };

  const handleRevokeSession = async (sessionId: string) => {
    try {
      await AuthService.revokeSession(sessionId);
      await loadSessions(); // Reload sessions
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke session");
    }
  };

  if (loading) {
    return (
      <Container size="sm" my={40}>
        <Paper withBorder shadow="sm" p={30} radius="md">
          <Text ta="center">Loading profile...</Text>
        </Paper>
      </Container>
    );
  }

  if (error) {
    return (
      <Container size="sm" my={40}>
        <Alert color="red" title="Error">
          {error}
        </Alert>
      </Container>
    );
  }

  if (!user) {
    return (
      <Container size="sm" my={40}>
        <Alert color="yellow" title="Not Authenticated">
          Please login to view your profile.
        </Alert>
      </Container>
    );
  }

  return (
    <Container size="lg" my={40}>
      {/* Header */}
      <Group justify="space-between" mb="xl">
        <Group gap="md">
          <Avatar size="lg" radius="md" color="blue">
            {user.first_name?.[0] || user.username?.[0] || "U"}
            {user.last_name?.[0] || user.username?.[1] || ""}
          </Avatar>
          <div>
            <Title order={2}>{user.first_name && user.last_name ? `${user.first_name} ${user.last_name}` : user.username || "User"}</Title>
            <Text size="sm" c="dimmed">
              {user.username ? `@${user.username}` : `ID: ${user.user_id || user.id || "Unknown"}`}
            </Text>
            {user.auth_type && (
              <Badge size="xs" variant="light" color="green" mt="xs">
                {user.auth_type.toUpperCase()} Auth
              </Badge>
            )}
          </div>
        </Group>

        <Group gap="sm">
          <Tooltip label="Refresh Profile">
            <ActionIcon variant="light" onClick={loadProfile} loading={loading}>
              <IconRefresh size={18} />
            </ActionIcon>
          </Tooltip>
          <Button leftSection={<IconLogout size={18} />} onClick={handleLogout} loading={logoutLoading} color="red" variant="light">
            Logout
          </Button>
        </Group>
      </Group>

      {/* Tabs */}
      <Tabs value={activeTab} onChange={(value) => setActiveTab(value || "profile")}>
        <Tabs.List>
          <Tabs.Tab value="profile" leftSection={<IconUser size={16} />}>
            Profile
          </Tabs.Tab>
          <Tabs.Tab value="sessions" leftSection={<IconDevices size={16} />}>
            Sessions
          </Tabs.Tab>
          <Tabs.Tab value="security" leftSection={<IconShield size={16} />}>
            Security
          </Tabs.Tab>
        </Tabs.List>

        {/* Profile Tab */}
        <Tabs.Panel value="profile" pt="md">
          <Grid>
            <Grid.Col span={12}>
              <Card withBorder shadow="sm" radius="md">
                <Card.Section withBorder inheritPadding py="xs">
                  <Group justify="space-between">
                    <Text fw={500}>Personal Information</Text>
                    <ActionIcon variant="subtle">
                      <IconSettings size={16} />
                    </ActionIcon>
                  </Group>
                </Card.Section>

                <Stack gap="md" mt="md">
                  {/* User ID */}
                  <Group justify="space-between">
                    <Group gap="sm">
                      <IconUser size={16} />
                      <Text size="sm" c="dimmed">
                        User ID:
                      </Text>
                    </Group>
                    <Text size="sm" ff="monospace">
                      {user.user_id || user.id || "N/A"}
                    </Text>
                  </Group>

                  {/* Username */}
                  {user.username && (
                    <>
                      <Divider />
                      <Group justify="space-between">
                        <Text size="sm" c="dimmed">
                          Username:
                        </Text>
                        <Text size="sm" fw={500}>
                          @{user.username}
                        </Text>
                      </Group>
                    </>
                  )}

                  {/* Email */}
                  {user.email && (
                    <>
                      <Divider />
                      <Group justify="space-between">
                        <Group gap="sm">
                          <IconMail size={16} />
                          <Text size="sm" c="dimmed">
                            Email:
                          </Text>
                        </Group>
                        <Text size="sm">{user.email}</Text>
                      </Group>
                    </>
                  )}

                  {/* Authentication Type */}
                  {user.auth_type && (
                    <>
                      <Divider />
                      <Group justify="space-between">
                        <Text size="sm" c="dimmed">
                          Auth Method:
                        </Text>
                        <Badge color="blue" variant="light" size="sm">
                          {user.auth_type.toUpperCase()}
                        </Badge>
                      </Group>
                    </>
                  )}

                  {/* Status */}
                  {user.is_active !== undefined && (
                    <>
                      <Divider />
                      <Group justify="space-between">
                        <Text size="sm" c="dimmed">
                          Status:
                        </Text>
                        <Badge color={user.is_active ? "green" : "red"} variant="light" size="sm">
                          {user.is_active ? "Active" : "Inactive"}
                        </Badge>
                      </Group>
                    </>
                  )}

                  {/* Verified */}
                  {user.is_verified !== undefined && (
                    <Group justify="space-between">
                      <Text size="sm" c="dimmed">
                        Verified:
                      </Text>
                      <Badge color={user.is_verified ? "blue" : "orange"} variant="light" size="sm">
                        {user.is_verified ? "Verified" : "Unverified"}
                      </Badge>
                    </Group>
                  )}

                  {/* Roles */}
                  {user.roles && user.roles.length > 0 && (
                    <>
                      <Divider />
                      <Group justify="space-between">
                        <Text size="sm" c="dimmed">
                          Roles:
                        </Text>
                        <Group gap="xs">
                          {user.roles.map((role, index) => (
                            <Badge key={index} variant="dot" size="sm">
                              {role}
                            </Badge>
                          ))}
                        </Group>
                      </Group>
                    </>
                  )}

                  {/* Member since */}
                  {user.created_at && (
                    <>
                      <Divider />
                      <Group justify="space-between">
                        <Group gap="sm">
                          <IconCalendar size={16} />
                          <Text size="sm" c="dimmed">
                            Member since:
                          </Text>
                        </Group>
                        <Text size="sm">{new Date(user.created_at).toLocaleDateString()}</Text>
                      </Group>
                    </>
                  )}

                  {/* API Response Info */}
                  {user.message && (
                    <>
                      <Divider />
                      <Alert color="blue" variant="light">
                        <Text size="sm">{user.message}</Text>
                      </Alert>
                    </>
                  )}

                  {/* Debug Info */}
                  <Divider />
                  <Group justify="space-between">
                    <Text size="xs" c="dimmed">
                      Session Status:
                    </Text>
                    <Badge color="green" variant="outline" size="xs">
                      Connected
                    </Badge>
                  </Group>
                </Stack>
              </Card>
            </Grid.Col>
          </Grid>
        </Tabs.Panel>

        {/* Sessions Tab */}
        <Tabs.Panel value="sessions" pt="md">
          <Card withBorder shadow="sm" radius="md">
            <Card.Section withBorder inheritPadding py="xs">
              <Group justify="space-between">
                <Text fw={500}>Active Sessions</Text>
                <Group gap="sm">
                  <Button size="xs" variant="light" onClick={loadSessions} loading={sessionsLoading} leftSection={<IconRefresh size={14} />}>
                    Refresh
                  </Button>
                </Group>
              </Group>
            </Card.Section>

            {sessionsLoading ? (
              <Center py="xl">
                <Loader size="sm" />
              </Center>
            ) : sessions.length > 0 ? (
              <Table striped highlightOnHover>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Device</Table.Th>
                    <Table.Th>Location</Table.Th>
                    <Table.Th>Last Active</Table.Th>
                    <Table.Th>Actions</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {sessions.map((session) => (
                    <Table.Tr key={session.session_id}>
                      <Table.Td>
                        <Group gap="sm">
                          <IconDevices size={16} />
                          <div>
                            <Text size="sm" fw={session.is_current ? 500 : 400}>
                              {session.user_agent.includes("Chrome")
                                ? "🟢 Chrome"
                                : session.user_agent.includes("Firefox")
                                ? "🟠 Firefox"
                                : session.user_agent.includes("Safari")
                                ? "🔵 Safari"
                                : "🖥️ Unknown"}
                            </Text>
                            {session.is_current && (
                              <Badge size="xs" variant="light" color="green">
                                Current
                              </Badge>
                            )}
                          </div>
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm" c="dimmed">
                          {session.ip_address}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm">{new Date(session.last_accessed).toLocaleString()}</Text>
                      </Table.Td>
                      <Table.Td>
                        {!session.is_current && (
                          <ActionIcon color="red" variant="subtle" onClick={() => handleRevokeSession(session.session_id)}>
                            <IconTrash size={16} />
                          </ActionIcon>
                        )}
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            ) : (
              <Text ta="center" py="xl" c="dimmed">
                No active sessions found
              </Text>
            )}
          </Card>
        </Tabs.Panel>

        {/* Security Tab */}
        <Tabs.Panel value="security" pt="md">
          <Stack gap="md">
            <Card withBorder shadow="sm" radius="md">
              <Card.Section withBorder inheritPadding py="xs">
                <Group gap="sm">
                  <IconShield size={18} />
                  <Text fw={500}>Security Actions</Text>
                </Group>
              </Card.Section>

              <Stack gap="md" mt="md">
                <Group justify="space-between">
                  <div>
                    <Text fw={500}>Revoke All Sessions</Text>
                    <Text size="sm" c="dimmed">
                      This will log you out of all devices and require re-authentication
                    </Text>
                  </div>
                  <Button color="red" variant="light" onClick={handleRevokeAll} loading={logoutLoading} leftSection={<IconTrash size={16} />}>
                    Revoke All
                  </Button>
                </Group>
              </Stack>
            </Card>

            <Alert color="blue" title="Authentication Status" icon={<IconEye size={16} />}>
              🔐 You are successfully authenticated with hybrid authentication (Cookie + JWT).
              <br />
              Your session is secure and all data is fetched from protected API endpoints.
            </Alert>

            <Card withBorder shadow="sm" radius="md">
              <Card.Section withBorder inheritPadding py="xs">
                <Text fw={500}>Raw Profile Data</Text>
              </Card.Section>

              <Paper bg="gray.0" p="md" mt="md" radius="sm">
                <Text size="xs" ff="monospace" style={{ whiteSpace: "pre-wrap" }}>
                  {JSON.stringify(user, null, 2)}
                </Text>
              </Paper>
            </Card>

            {sessions.length > 0 && (
              <Card withBorder shadow="sm" radius="md">
                <Card.Section withBorder inheritPadding py="xs">
                  <Text fw={500}>Raw Session Data</Text>
                </Card.Section>

                <Paper bg="gray.0" p="md" mt="md" radius="sm">
                  <Text size="xs" ff="monospace" style={{ whiteSpace: "pre-wrap" }}>
                    {JSON.stringify(sessions, null, 2)}
                  </Text>
                </Paper>
              </Card>
            )}
          </Stack>
        </Tabs.Panel>
      </Tabs>
    </Container>
  );
}
