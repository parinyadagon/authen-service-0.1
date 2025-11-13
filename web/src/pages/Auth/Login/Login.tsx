import { useState } from "react";
import { Anchor, Button, Checkbox, Container, Group, Paper, PasswordInput, Text, TextInput, Title, Alert } from "@mantine/core";
import { useForm } from "@mantine/form";
import classes from "./Login.module.css";
import { AuthService } from "../../../services/auth.service";
import type { LoginRequest } from "../../../types/auth.types";
import { useNavigate } from "react-router";

export function Login() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const navigate = useNavigate();

  const form = useForm<LoginRequest>({
    initialValues: {
      username: "",
      password: "",
      remember: false,
    },
    validate: {
      username: (value) => (!value ? "Username is required" : null),
      password: (value) => (!value ? "Password is required" : null),
    },
  });

  const handleSubmit = async (values: LoginRequest) => {
    setLoading(true);
    setError(null);

    try {
      const response = await AuthService.login(values);
      setSuccess(true);

      // Redirect or handle successful login
      console.log("Login successful:", response);

      // You can redirect here or emit an event to parent component
      // window.location.href = '/dashboard';
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    // Auto redirect after 1 second
    setTimeout(() => {
      navigate("/profile");
    }, 1000);

    return (
      <Container size={420} my={40}>
        <Alert color="green" title="Login Successful">
          You have been successfully logged in! Redirecting to profile...
        </Alert>
      </Container>
    );
  }

  return (
    <Container size={420} my={40}>
      <Title ta="center" className={classes.title}>
        Welcome back!
      </Title>

      <Text className={classes.subtitle}>
        Do not have an account yet? <Anchor>Create account</Anchor>
      </Text>

      <Paper withBorder shadow="sm" p={22} mt={30} radius="md">
        <form onSubmit={form.onSubmit(handleSubmit)}>
          {error && (
            <Alert color="red" mb="md">
              {error}
            </Alert>
          )}

          <TextInput label="Username" placeholder="Enter your username" required radius="md" {...form.getInputProps("username")} />

          <PasswordInput label="Password" placeholder="Your password" required mt="md" radius="md" {...form.getInputProps("password")} />

          <Group justify="space-between" mt="lg">
            <Checkbox label="Remember me" {...form.getInputProps("remember", { type: "checkbox" })} />
            <Anchor component="button" size="sm" type="button">
              Forgot password?
            </Anchor>
          </Group>

          <Button fullWidth mt="xl" radius="md" type="submit" loading={loading} disabled={loading}>
            {loading ? "Signing in..." : "Sign in"}
          </Button>

          {/* Demo credentials hint */}
          <Text size="xs" ta="center" mt="md" c="dimmed">
            Demo: testadmin / admin123
          </Text>
        </form>

        <Text ta="center" mt="md">
          Don&apos;t have an account?{" "}
          <Anchor href="#" fw={500} onClick={(event) => event.preventDefault()}>
            Register
          </Anchor>
        </Text>
      </Paper>
    </Container>
  );
}
