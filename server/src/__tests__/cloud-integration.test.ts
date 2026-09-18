/**
 * Intune / XDR integration — pure logic tests.
 *
 * Graph is never called here. Payload shapes follow the Microsoft Graph beta
 * reference for deviceManagementConfigurationPolicy (settings catalog),
 * windows10CustomConfiguration (OMA-URI), assignment targets, and
 * security/runHuntingQuery results.
 */

import * as fs from "fs";
import * as path from "path";
import {
  normalizeSettingsCatalogPolicy,
  normalizeOmaUriPolicy,
  isAppControlOmaProfile,
  normalizeAssignment,
  decodePolicyPayload,
  evaluateEffectiveAssignment,
  buildAppControlEventsQuery,
  buildDeviceLookupQuery,
  normalizeManagedDevice,
  APP_CONTROL_DECISION_ACTION_TYPES,
} from "@appcontrol/shared";
import { parseAdvancedHuntingJson } from "../services/event-parser.js";
import { parseWdacXml } from "../services/xml-parser.js";
import { buildPolicyFromEvents } from "../services/policy-builder.js";

const TEMPLATES = path.join(__dirname, "../../templates");
const ALLOW_MS_XML = fs.readFileSync(path.join(TEMPLATES, "AllowMicrosoft.xml"), "utf8");
const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");
const GROUP_PILOT = "aaaaaaaa-0000-0000-0000-000000000001";
const GROUP_EXCL = "aaaaaaaa-0000-0000-0000-000000000002";
const GROUP_USERS = "aaaaaaaa-0000-0000-0000-000000000003";

describe("Intune assignment normalisation", () => {
  test("maps every Graph target type", () => {
    const mk = (t: string, extra = {}) => normalizeAssignment({ id: "x", target: { "@odata.type": `#microsoft.graph.${t}`, ...extra } });
    expect(mk("allDevicesAssignmentTarget").kind).toBe("allDevices");
    expect(mk("allLicensedUsersAssignmentTarget").kind).toBe("allUsers");
    expect(mk("groupAssignmentTarget", { groupId: GROUP_PILOT })).toMatchObject({ kind: "group", groupId: GROUP_PILOT });
    expect(mk("exclusionGroupAssignmentTarget", { groupId: GROUP_EXCL }).kind).toBe("exclusionGroup");
    const f = mk("allDevicesAssignmentTarget", { deviceAndAppManagementAssignmentFilterId: "f1", deviceAndAppManagementAssignmentFilterType: "include" });
    expect(f.filterId).toBe("f1");
    expect(f.filterType).toBe("include");
    expect(mk("allDevicesAssignmentTarget", { deviceAndAppManagementAssignmentFilterType: "none" }).filterType).toBe("none");
  });
});

describe("policy payload decoding", () => {
  test("plain XML, base64 UTF-8 XML, base64 UTF-16LE XML, and binary CIP", () => {
    expect(decodePolicyPayload(ALLOW_MS_XML)?.kind).toBe("xml");
    expect(decodePolicyPayload(b64(ALLOW_MS_XML))?.kind).toBe("xml");
    const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(ALLOW_MS_XML, "utf16le")]).toString("base64");
    const d = decodePolicyPayload(utf16);
    expect(d?.kind).toBe("xml");
    expect(parseWdacXml((d as { xml: string }).xml).policy.signers).toHaveLength(18);
    const cip = Buffer.alloc(2000, 7).toString("base64");
    expect(decodePolicyPayload(cip)).toMatchObject({ kind: "binary" });
    expect(decodePolicyPayload("Enabled")).toBeNull();
    expect(decodePolicyPayload("1")).toBeNull();
  });
});

describe("settings catalog App Control policy", () => {
  const raw = {
    id: "pol-1",
    name: "WDAC — Allow Microsoft (audit)",
    description: "Pilot",
    platforms: "windows10",
    technologies: "mdm",
    lastModifiedDateTime: "2026-09-01T10:00:00Z",
    templateReference: { templateFamily: "endpointSecurityApplicationControl" },
    assignments: [
      { id: "a1", target: { "@odata.type": "#microsoft.graph.groupAssignmentTarget", groupId: GROUP_PILOT, deviceAndAppManagementAssignmentFilterId: "flt-1", deviceAndAppManagementAssignmentFilterType: "include" } },
      { id: "a2", target: { "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget", groupId: GROUP_EXCL } },
    ],
    settings: [
      {
        id: "0",
        settingInstance: {
          "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
          settingDefinitionId: "device_vendor_msft_policy_config_applicationcontrol_configurationtype",
          choiceSettingValue: {
            value: "device_vendor_msft_policy_config_applicationcontrol_configurationtype_xml",
            children: [
              {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                settingDefinitionId: "device_vendor_msft_policy_config_applicationcontrol_policyxml",
                simpleSettingValue: { "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue", value: b64(ALLOW_MS_XML) },
              },
            ],
          },
        },
      },
    ],
  };

  test("flattens nested settings, decodes the XML and keeps assignments", () => {
    const p = normalizeSettingsCatalogPolicy(raw);
    expect(p.source).toBe("settingsCatalog");
    expect(p.settingCount).toBe(2);
    expect(p.xmlPolicies).toHaveLength(1);
    expect(parseWdacXml(p.xmlPolicies[0].xml).policy.friendlyName).toBe("DefaultMicrosoftEnforced");
    expect(p.assignments.map((a) => a.kind)).toEqual(["group", "exclusionGroup"]);
    expect(p.assignments[0].filterType).toBe("include");
    expect(p.portalUrl).toContain("pol-1");
  });

  test("built-in controls mode is summarised when no XML is present", () => {
    const p = normalizeSettingsCatalogPolicy({
      id: "pol-2", name: "Built-in",
      settings: [{ settingInstance: {
        settingDefinitionId: "device_vendor_msft_policy_config_applicationcontrol_configurationtype",
        choiceSettingValue: { value: "..._builtincontrols", children: [
          { settingDefinitionId: "device_vendor_msft_policy_config_applicationcontrol_enableauditmode", choiceSettingValue: { value: "device_vendor_msft_policy_config_applicationcontrol_enableauditmode_1" } },
          { settingDefinitionId: "device_vendor_msft_policy_config_applicationcontrol_trustappswithgoodreputation", choiceSettingValue: { value: "..._trustappswithgoodreputation_1" } },
          { settingDefinitionId: "device_vendor_msft_policy_config_applicationcontrol_trustappsfrommanagedinstallers", choiceSettingValue: { value: "..._trustappsfrommanagedinstallers_0" } },
        ] },
      } }],
    });
    expect(p.xmlPolicies).toHaveLength(0);
    expect(p.builtInControls).toEqual(expect.arrayContaining(["Audit mode", "Trust apps with good reputation (ISG)"]));
    expect(p.builtInControls).not.toContain("Trust apps from managed installers");
  });
});

describe("custom OMA-URI App Control profile", () => {
  const raw = {
    "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
    id: "prof-1",
    displayName: "WDAC legacy",
    assignments: [{ id: "a", target: { "@odata.type": "#microsoft.graph.allDevicesAssignmentTarget" } }],
    omaSettings: [
      { "@odata.type": "#microsoft.graph.omaSettingBase64", displayName: "policy", omaUri: "./Vendor/MSFT/ApplicationControl/Policies/{959A0F15-8985-4551-A208-5FFE9EDB3A70}/Policy", value: b64(ALLOW_MS_XML) },
      { "@odata.type": "#microsoft.graph.omaSettingBase64", displayName: "bin", omaUri: "./Vendor/MSFT/ApplicationControl/Policies/{11111111-1111-1111-1111-111111111111}/Policy", value: Buffer.alloc(4096, 1).toString("base64") },
      { "@odata.type": "#microsoft.graph.omaSettingString", displayName: "unrelated", omaUri: "./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate", value: "2" },
    ],
  };

  test("is recognised and decoded, ignoring unrelated OMA-URIs", () => {
    expect(isAppControlOmaProfile(raw)).toBe(true);
    expect(isAppControlOmaProfile({ "@odata.type": "#microsoft.graph.windows10GeneralConfiguration" })).toBe(false);
    const p = normalizeOmaUriPolicy(raw);
    expect(p.source).toBe("customOmaUri");
    expect(p.settingCount).toBe(2);
    expect(p.xmlPolicies).toEqual([expect.objectContaining({ label: "959A0F15-8985-4551-A208-5FFE9EDB3A70" })]);
    expect(p.binaryPolicies).toEqual([expect.objectContaining({ label: "11111111-1111-1111-1111-111111111111" })]);
    expect(p.assignments[0].kind).toBe("allDevices");
  });
});

describe("effective assignment evaluation", () => {
  const policy = {
    id: "p",
    assignments: [
      { kind: "group" as const, groupId: GROUP_PILOT, groupName: "WDAC Pilot" },
      { kind: "exclusionGroup" as const, groupId: GROUP_EXCL, groupName: "WDAC Exclusions" },
    ],
  };

  test("device in the pilot group is assigned; in the exclusion group it is excluded", () => {
    const a = evaluateEffectiveAssignment(policy, { deviceGroupIds: [GROUP_PILOT], hasPrimaryUser: false });
    expect(a.status).toBe("assigned");
    expect(a.reasons[0]).toContain("WDAC Pilot");
    const e = evaluateEffectiveAssignment(policy, { deviceGroupIds: [GROUP_PILOT, GROUP_EXCL], hasPrimaryUser: false });
    expect(e.status).toBe("excluded");
    const n = evaluateEffectiveAssignment(policy, { deviceGroupIds: ["other"], hasPrimaryUser: false });
    expect(n.status).toBe("notAssigned");
  });

  test("user-group and All-users targeting go through the primary user", () => {
    const userPolicy = { id: "u", assignments: [{ kind: "group" as const, groupId: GROUP_USERS, groupName: "Finance" }] };
    expect(evaluateEffectiveAssignment(userPolicy, { deviceGroupIds: [], userGroupIds: [GROUP_USERS], hasPrimaryUser: true }).status).toBe("assigned");
    const all = { id: "a", assignments: [{ kind: "allUsers" as const }] };
    expect(evaluateEffectiveAssignment(all, { deviceGroupIds: [], hasPrimaryUser: true }).status).toBe("assigned");
    const noUser = evaluateEffectiveAssignment(all, { deviceGroupIds: [], hasPrimaryUser: false });
    expect(noUser.status).toBe("notAssigned");
    expect(noUser.reasons[0]).toMatch(/no primary user/);
  });

  test("filters are surfaced as notes, not evaluated", () => {
    const filtered = { id: "f", assignments: [{ kind: "allDevices" as const, filterId: "flt", filterType: "exclude" as const, filterName: "Servers" }] };
    const r = evaluateEffectiveAssignment(filtered, { deviceGroupIds: [], hasPrimaryUser: false });
    expect(r.status).toBe("assigned");
    expect(r.filterNotes[0]).toMatch(/exclude filter 'Servers'/);
  });
});

describe("Advanced Hunting", () => {
  test("query escapes quotes and backslashes and includes every decision action type", () => {
    const q = buildAppControlEventsQuery({ deviceName: 'pc"1\\x', blockedOnly: true, limit: 50 });
    expect(q).toContain('"pc\\"1\\\\x"');
    expect(q).toContain('| where ActionType endswith "Blocked"');
    expect(q).toContain("| take 50");
    for (const t of APP_CONTROL_DECISION_ACTION_TYPES) expect(q).toContain(`"${t}"`);
    expect(buildAppControlEventsQuery({ deviceId: "abc" })).toContain('DeviceId == "abc"');
    expect(buildAppControlEventsQuery({ limit: 999999 })).toContain("| take 10000");
    expect(buildDeviceLookupQuery("LAPTOP")).toContain("DeviceInfo");
  });

  test("hunting rows flow through the Advanced Hunting parser into a supplemental policy", () => {
    const rows = [
      {
        Timestamp: "2026-09-17T09:00:00Z", DeviceName: "laptop-042.contoso.com", DeviceId: "d1",
        ActionType: "AppControlCodeIntegrityPolicyBlocked", FileName: "tool.exe", FolderPath: "C:\\Program Files\\Vendor",
        SHA256: "A".repeat(64), SHA1: "B".repeat(40), InitiatingProcessFileName: "explorer.exe",
        PolicyName: "Corp WDAC", PolicyGuid: "{22222222-2222-2222-2222-222222222222}", PolicyId: "Corp WDAC",
        OriginalFileName: "tool.exe", ProductName: "Vendor Tool", FileVersion: "1.2.3.4", PublisherName: "Vendor Inc", IssuerName: "DigiCert",
      },
      {
        Timestamp: "2026-09-17T09:05:00Z", DeviceName: "laptop-042.contoso.com", DeviceId: "d1",
        ActionType: "AppControlCIScriptAudited", FileName: "deploy.ps1", FolderPath: "C:\\Scripts",
        SHA256: "C".repeat(64), SHA1: "", PolicyName: "Corp WDAC", PolicyGuid: "{22222222-2222-2222-2222-222222222222}",
      },
    ];
    const parsed = parseAdvancedHuntingJson(JSON.stringify(rows));
    expect(parsed.events).toHaveLength(2);
    expect(parsed.summary.blockEvents).toBe(1);
    expect(parsed.events[0].filePath).toBe("C:\\Program Files\\Vendor\\tool.exe");
    expect(parsed.events[0].sha256FlatHash).toBe("A".repeat(64));
    expect(parsed.events[0].signerInfo?.publisherName).toBe("Vendor Inc");
    const { policy } = buildPolicyFromEvents({ events: parsed.events, policyName: "From XDR", policyType: "Supplemental", preferPublisherRules: false, includePathRules: false, auditMode: true });
    expect(policy.basePolicyId).toBe("22222222-2222-2222-2222-222222222222");
    expect(policy.fileRules.filter((r) => r.kind === "hash")).toHaveLength(3); // sha1+sha256 for tool.exe, sha256 for deploy.ps1
  });
});

describe("managed device normalisation", () => {
  test("keeps the fields the Devices tab needs", () => {
    const d = normalizeManagedDevice({ id: "1", deviceName: "LAPTOP-042", azureADDeviceId: "aad-1", userPrincipalName: "jane@contoso.com", userId: "u1", operatingSystem: "Windows", osVersion: "10.0.26100.1", complianceState: "compliant", serialNumber: null });
    expect(d).toMatchObject({ id: "1", deviceName: "LAPTOP-042", azureADDeviceId: "aad-1", userId: "u1", complianceState: "compliant" });
    expect(d.serialNumber).toBeUndefined();
  });
});
