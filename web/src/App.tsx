import { Route, Routes } from "react-router";

import { Login } from "@/pages/Auth";
import { Profile } from "@/pages/Profile/Profile";

function App() {
  return (
    <Routes>
      <Route path="" element={<Login />} />
      <Route path="/profile" element={<Profile />} />
    </Routes>
  );
}

export default App;
