import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Sidebar } from "./components/layout/Sidebar.tsx";
import { PolicyEditorPage } from "./pages/PolicyEditorPage.tsx";
import { ComparePage } from "./pages/ComparePage.tsx";
import { ImportEventsPage } from "./pages/ImportEventsPage.tsx";
import { BuildPolicyPage } from "./pages/BuildPolicyPage.tsx";
import { ExportPage } from "./pages/ExportPage.tsx";

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen overflow-hidden">
        <Sidebar />
        <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <Routes>
            <Route path="/" element={<PolicyEditorPage />} />
            <Route path="/compare" element={<ComparePage />} />
            <Route path="/import-events" element={<ImportEventsPage />} />
            <Route path="/build" element={<BuildPolicyPage />} />
            <Route path="/export" element={<ExportPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
