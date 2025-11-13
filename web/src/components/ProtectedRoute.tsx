import { useEffect } from "react";
import { useNavigate } from "react-router";
import { Loader, Container, Center } from "@mantine/core";
import { useAuth } from "../hooks/useAuth";

interface ProtectedRouteProps {
  children: React.ReactNode;
  redirectTo?: string;
}

export function ProtectedRoute({ children, redirectTo = "/" }: ProtectedRouteProps) {
  const { isAuthenticated, loading } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!loading && !isAuthenticated) {
      console.log("🔒 User not authenticated, redirecting to:", redirectTo);
      navigate(redirectTo, { replace: true });
    }
  }, [isAuthenticated, loading, navigate, redirectTo]);

  if (loading) {
    return (
      <Container size="sm" my={40}>
        <Center h={200}>
          <Loader size="lg" />
        </Center>
      </Container>
    );
  }

  if (!isAuthenticated) {
    return null; // Will redirect
  }

  return <>{children}</>;
}
