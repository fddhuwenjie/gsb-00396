import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Home from "@/pages/Home";
import CertificateDetail from "@/pages/CertificateDetail";

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/certificate" element={<CertificateDetail />} />
      </Routes>
    </Router>
  );
}
