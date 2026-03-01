import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Sidebar } from "./components/layout/Sidebar.tsx";
import { PolicyEditorPage } from "./pages/PolicyEditorPage.tsx";
import { ComparePage } from "./pages/ComparePage.tsx";
import { ImportEventsPage } from "./pages/ImportEventsPage.tsx";
import { BuildPolicyPage } from "./pages/BuildPolicyPage.tsx";
import { ExportPage } from "./pages/ExportPage.tsx";
import { RuleEnginePage } from "./pages/RuleEnginePage.tsx";
import { SemanticComparePage } from "./pages/SemanticComparePage.tsx";
import { AdvancedHuntingPage } from "./pages/AdvancedHuntingPage.tsx";
import { SecurityPage } from "./pages/SecurityPage.tsx";

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen overflow-hidden">
        <Sidebar />
        <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <Routes>
            <Route path="/" element={<PolicyEditorPage />} />
            <Route path="/compare" element={<ComparePage />} />
            <Route path="/semantic-compare" element={<SemanticComparePage />} />
            <Route path="/advanced-hunting" element={<AdvancedHuntingPage />} />
            <Route path="/import-events" element={<ImportEventsPage />} />
            <Route path="/build" element={<BuildPolicyPage />} />
            <Route path="/export" element={<ExportPage />} />
            <Route path="/rule-engine" element={<RuleEnginePage />} />
            <Route path="/security" element={<SecurityPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
