import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Sidebar } from "./components/layout/Sidebar.tsx";
import { PolicyEditorPage } from "./pages/PolicyEditorPage.tsx";
import { ComparePage } from "./pages/ComparePage.tsx";
import { ImportEventsPage } from "./pages/ImportEventsPage.tsx";
import { ExportPage } from "./pages/ExportPage.tsx";
import { RuleEnginePage } from "./pages/RuleEnginePage.tsx";
import { SecurityPage } from "./pages/SecurityPage.tsx";
import { SimulatorPage } from "./pages/SimulatorPage.tsx";
import { MergePage } from "./pages/MergePage.tsx";
import { AppLockerPage } from "./pages/AppLockerPage.tsx";
import { FileInspectorPage } from "./pages/FileInspectorPage.tsx";
import { CreatePolicyPage } from "./pages/CreatePolicyPage.tsx";
import { ValidatePage } from "./pages/ValidatePage.tsx";
import { CloudPage } from "./pages/CloudPage.tsx";

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
            <Route path="/export" element={<ExportPage />} />
            <Route path="/rule-engine" element={<RuleEnginePage />} />
            <Route path="/security" element={<SecurityPage />} />
            <Route path="/simulator" element={<SimulatorPage />} />
            <Route path="/merge" element={<MergePage />} />
            <Route path="/applocker" element={<AppLockerPage />} />
            <Route path="/create" element={<CreatePolicyPage />} />
            <Route path="/files" element={<FileInspectorPage />} />
            <Route path="/validate" element={<ValidatePage />} />
            <Route path="/cloud" element={<CloudPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
