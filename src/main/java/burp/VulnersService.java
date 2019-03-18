package burp;


import burp.gui.TabComponent;
import burp.models.Domain;
import burp.models.Software;
import burp.models.Vulnerability;
import com.codemagi.burp.MatchRule;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import com.google.common.util.concurrent.RateLimiter;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.table.DefaultTableModel;
import java.io.IOException;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;


public class VulnersService {

    private BurpExtender burpExtender;
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final TabComponent tabComponent;
    private Map<String, Domain> domains;

    private final RateLimiter rateLimiter;

    private final HttpClient httpClient;

    VulnersService(BurpExtender burpExtender, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, Map<String, Domain> domains, TabComponent tabComponent) {
        this.burpExtender = burpExtender;
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.domains = domains;
        this.tabComponent = tabComponent;
        this.rateLimiter = RateLimiter.create(4.0);  // Count of max RPS

        this.httpClient = new HttpClient(callbacks, helpers, burpExtender);
    }


    /**
     * Check found software for vulnerabilities using https://vulnes.com/api/v3/burp/software/
     *
     * @param domainName
     * @param software
     * @param baseRequestResponse
     * @param startStop
     */
    void checkSoftware(final String domainName, final Software software, final IHttpRequestResponse baseRequestResponse, final List<int[]> startStop) {

        // Limiting requests rate
        // TODO make non block MQ
        rateLimiter.acquire();

        try {
            if (software.getVersion() != null) {
                JSONObject data = httpClient.get("software", new HashMap<String, String>(){{
                    put("software", software.getAlias());
                    put("version", software.getVersion());
                    put("type", software.getMatchType());
                }});

                Set<Vulnerability> vulnerabilities = getVulnerabilities(data);

                for (Vulnerability vulnerability : vulnerabilities) {
                    // update cache
                    domains.get(domainName)
                            .getSoftware()
                            .get(software.getKey())
                            .getVulnerabilities()
                            .add(vulnerability);
                }

                // update gui component
                tabComponent.getSoftwareTable().refreshTable(domains, tabComponent.getCbxSoftwareShowVuln().isSelected());
            }

            // add Burp issue
            callbacks.addScanIssue(new SoftwareIssue(
                    baseRequestResponse,
                    helpers,
                    callbacks,
                    startStop,
                    domains.get(domainName).getSoftware().get(software.getKey())
            ));
        } catch (Exception e) {
            callbacks.printError(e.getMessage());
        }
    }

    /**
     * Check found software for vulnerabilities using https://vulnes.com/api/v3/burp/path/
     *
     * @param domainName
     * @param path
     * @param baseRequestResponse
     */
    void checkURLPath(final String domainName, final String path, final IHttpRequestResponse baseRequestResponse) {
        // Limiting requests rate
        // TODO make non block MQ
        rateLimiter.acquire();

        JSONObject data = httpClient.get("path", new HashMap<String, String>(){{
            put("path", path);
        }});

        Set<Vulnerability> vulnerabilities = getVulnerabilities(data);

        if (vulnerabilities.isEmpty()) {
            callbacks.printOutput("No Vulnerabilities - " + path);
            return;
        }

        // update cache
        domains.get(domainName)
                .getPaths()
                .put(path, vulnerabilities);

        // update gui component
        tabComponent.getPathsTable().getDefaultModel().addRow(new Object[]{
                domainName,
                path,
                Utils.getMaxScore(vulnerabilities),
                Utils.getVulnersList(vulnerabilities)
        });

        // add Burp issue
        callbacks.addScanIssue(new PathIssue(
                baseRequestResponse,
                helpers,
                callbacks,
                path,
                vulnerabilities
        ));
    }

    private Set<Vulnerability> getVulnerabilities(JSONObject data) {
        Set<Vulnerability> vulnerabilities = new HashSet<>();

        if (!data.has("search")) {
            return vulnerabilities;
        }

        JSONArray bulletins = data.getJSONArray("search");
        for (Object bulletin : bulletins) {
            vulnerabilities.add(
                new Vulnerability(((JSONObject) bulletin).getJSONObject("_source"))
            );
        }
        return vulnerabilities;
    }

    /**
     * Check out rules for matching
     */
    public void loadRules() throws IOException {

        JSONObject data = httpClient.get("rules", new HashMap<String, String>());

        JSONObject rules = data.getJSONObject("rules");
        Iterator<String> ruleKeys = rules.keys();

        DefaultTableModel ruleModel = tabComponent.getRulesTable().getDefaultModel();
        ruleModel.setRowCount(0); //reset table
        while (ruleKeys.hasNext()) {
            String key = ruleKeys.next();
            final JSONObject v = rules.getJSONObject(key);

            ruleModel.addRow(new Object[]{key, v.getString("regex"), v.getString("alias"), v.getString("type")});

            try {
                Pattern pattern = Pattern.compile(v.getString("regex"));
                System.out.println("[NEW] " + pattern);

                burpExtender.getMatchRules().put(key, new HashMap<String, String>() {{
                    put("regex", v.getString("regex"));
                    put("alias", v.getString("alias"));
                    put("type", v.getString("type"));
                }});
                // Match group 1 - is important
                burpExtender.addMatchRule(new MatchRule(pattern, 1, key, ScanIssueSeverity.LOW, ScanIssueConfidence.CERTAIN));
            } catch (PatternSyntaxException pse) {
                callbacks.printError("Unable to compile pattern: " + v.getString("regex") + " for: " + key);
                burpExtender.printStackTrace(pse);
            }
        }
    }

}
