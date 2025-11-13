import { useState } from "react";
import { Anchor, Button, Checkbox, Container, Group, Paper, PasswordInput, Text, TextInput, Title, Alert } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useNavigate } from "react-router";
import classes from "./Login.module.css";
import { useAuth } from "../../../hooks/useAuth";
import type { LoginRequest } from "../../../types/auth.types";
export function Login() {
  const { login, loading, error } = useAuth();
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
    try {
      await login(values);
      setSuccess(true);
      console.log("Login successful - redirecting to profile");
      // Manual redirect for immediate navigation
      navigate("/profile");
    } catch (err) {
      // Error is handled by useAuth hook
      console.error("Login failed:", err);
    }
  };

  if (success) {
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
