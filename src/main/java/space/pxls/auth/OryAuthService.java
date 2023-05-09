package space.pxls.auth;

import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import kong.unirest.json.JSONObject;
import space.pxls.App;

public class OryAuthService extends AuthService {
    public OryAuthService(String id) {
        super(id, App.getConfig().getBoolean("oauth.ory.enabled"), App.getConfig().getBoolean("oauth.ory.registrationEnabled"));
    }

    @Override
    public String getRedirectUrl(String state) {
        return  App.getConfig().getString("oauth.ory.baseurl") + "/oauth2/auth?" +
                "scope=profile%20email%20id&" +
                "access_type=online&" +
                "state=" + state + "&" +
                "redirect_uri=" + getCallbackUrl() + "&" +
                "response_type=authorization_code&" +
                "client_id=" + App.getConfig().getString("oauth.ory.key");
    }

    @Override
    public String getToken(String code) throws UnirestException {
        HttpResponse<JsonNode> response = Unirest.post(App.getConfig().getString("oauth.ory.baseurl") +"/oauth2/token")
                .header("User-Agent", "pxls.space")
                .field("grant_type", "authorization_code")
                .field("code", code)
                .field("redirect_uri", getCallbackUrl())
                .field("client_id", App.getConfig().getString("oauth.ory.key"))
                .field("client_secret", App.getConfig().getString("oauth.ory.secret"))
                .asJson();

        JSONObject json = response.getBody().getObject();

        if (json.has("error")) {
            return null;
        } else {
            return json.getString("access_token");
        }
    }

    @Override
    public String getIdentifier(String token) throws UnirestException {
        HttpResponse<JsonNode> me = Unirest.get(App.getConfig().getString("oauth.ory.baseurl") + "/oauth2/userinfo")
                .header("Authorization", "Bearer " + token)
                .header("User-Agent", "pxls.space")
                .asJson();
        JSONObject json = me.getBody().getObject();
        if (json.has("error")) {
            return null;
        } else {
            return json.getString("id");
        }
    }

    public String getName() {
        return "Ory";
    }

    @Override
    public void reloadEnabledState() {
        this.enabled = App.getConfig().getBoolean("oauth.ory.enabled");
        this.registrationEnabled = App.getConfig().getBoolean("oauth.ory.registrationEnabled");
    }
}
