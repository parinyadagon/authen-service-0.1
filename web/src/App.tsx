import { Route, Routes } from "react-router";

import { Login } from "@/pages/Auth";
import { Authorize } from "@/pages/Auth/Authorize/Authorize";
import { Profile } from "@/pages/Profile/Profile";
import { ProtectedRoute, PublicRoute } from "@/components";

function App() {
  return (
    <Routes>
      <Route
        path=""
        element={
          <PublicRoute>
            <Login />
          </PublicRoute>
        }
      />
      <Route
        path="/oauth/authorize"
        element={
          <ProtectedRoute redirectTo="/">
            <Authorize />
          </ProtectedRoute>
        }
      />
      <Route
        path="/profile"
        element={
          <ProtectedRoute>
            <Profile />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}

export default App;
