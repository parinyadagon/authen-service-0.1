import { useEffect } from "react";
import { useNavigate } from "react-router";
import { useAuth } from "../hooks/useAuth";

interface PublicRouteProps {
  children: React.ReactNode;
  redirectTo?: string;
}

export function PublicRoute({ children, redirectTo = "/profile" }: PublicRouteProps) {
  const { isAuthenticated, loading } = useAuth();
  const navigate = useNavigate();

  console.log("🔍 PublicRoute state:", { isAuthenticated, loading });

  useEffect(() => {
    console.log("🔄 PublicRoute useEffect:", { isAuthenticated, loading });
    if (!loading && isAuthenticated) {
      console.log("✅ User authenticated, redirecting to:", redirectTo);
      navigate(redirectTo, { replace: true });
    }
  }, [isAuthenticated, loading, navigate, redirectTo]);

  if (loading) {
    return <>{children}</>;
  }

  if (isAuthenticated) {
    return null; // Will redirect
  }

  return <>{children}</>;
}
