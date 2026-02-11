import{j as e,i as s,a as r,b as a,c as i,o as t}from"../chunks/chunk-CUuCKY5k.js";import"../chunks/chunk-xUHxWF9R.js";/* empty css                      *//* empty css                      */const o=()=>e.jsxs("div",{className:"max-w-4xl mx-auto px-6 py-20",children:[e.jsx("a",{href:"/blog",className:"text-blue-600 hover:text-blue-800 mb-6 inline-block",children:"← Back to Blog"}),e.jsxs("article",{className:"prose prose-lg max-w-none",children:[e.jsx("div",{className:"text-sm text-gray-500 mb-2",children:"September 1, 2021"}),e.jsx("h1",{className:"text-4xl font-medium mb-6",children:"Fine-Grained Authorization with Keycloak UMA: Building Dynamic Resource Access Control"}),e.jsx("p",{className:"text-xl text-gray-600 mb-8",children:"Modern applications increasingly require sophisticated authorization mechanisms that go beyond simple role-based access control. Learn how to architect a system where users dynamically create resources and manage fine-grained permissions through Keycloak's User-Managed Access (UMA) 2.0 implementation."}),e.jsx("h2",{className:"text-2xl font-medium mt-8 mb-4",children:"The Use Case"}),e.jsx("p",{className:"mb-4",children:"Consider a multi-tenant SaaS platform where users dynamically create resources—documents, projects, or in our case, car records—and need granular control over who can access them. Our application has the following requirements:"}),e.jsxs("ul",{className:"list-disc pl-6 mb-4",children:[e.jsx("li",{className:"mb-2",children:"A backend server creates car resources dynamically at runtime"}),e.jsx("li",{className:"mb-2",children:"Each car resource should be individually protected"}),e.jsx("li",{className:"mb-2",children:"Resource owners need a self-service interface to grant read/write permissions"}),e.jsx("li",{className:"mb-2",children:"Authorization decisions combine attribute-based (ABAC) and role-based (RBAC) policies"}),e.jsx("li",{className:"mb-2",children:"The solution must scale to thousands of dynamically created resources"})]}),e.jsx("h2",{className:"text-2xl font-medium mt-8 mb-4",children:"Understanding Keycloak's Authorization Architecture"}),e.jsx("p",{className:"mb-4",children:"Before diving into implementation, let's clarify Keycloak's authorization primitives:"}),e.jsx("h3",{className:"text-xl font-medium mt-6 mb-3",children:"Resource Server"}),e.jsx("p",{className:"mb-4",children:`The resource server is the application you're protecting—in our case, the backend API that manages car resources. In Keycloak, you register your API as a client with "Authorization Enabled" turned on. This transforms a standard OAuth2/OIDC client into a resource server capable of enforcing fine-grained permissions.`}),e.jsx("p",{className:"mb-4",children:"When you enable authorization for a client, Keycloak provisions an authorization configuration for that resource server, including dedicated endpoints for managing resources, scopes, policies, and permissions."}),e.jsx("h3",{className:"text-xl font-medium mt-6 mb-3",children:"Resources"}),e.jsx("p",{className:"mb-4",children:"Resources represent the protected objects in your system. In our scenario, each car is a resource. Resources can be registered programmatically via Keycloak's Protection API, which is critical for dynamic scenarios."}),e.jsx("p",{className:"mb-4",children:"A resource definition includes:"}),e.jsxs("ul",{className:"list-disc pl-6 mb-4",children:[e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Name and URI:"})," Logical identifier and optional URI pattern (e.g., ",e.jsx("code",{children:"/car/123"}),")"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Type:"})," Optional categorization (e.g., ",e.jsx("code",{children:"urn:myapp:resources:car"}),")"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Scopes:"})," Associated actions that can be performed"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Owner:"})," The user who owns this resource (crucial for UMA)"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Attributes:"})," Custom metadata for policy evaluation"]})]}),e.jsx("h3",{className:"text-xl font-medium mt-6 mb-3",children:"Scopes"}),e.jsx("p",{className:"mb-4",children:"Scopes define the actions that can be performed on resources. For our use case, we define two scopes:"}),e.jsxs("ul",{className:"list-disc pl-6 mb-4",children:[e.jsxs("li",{className:"mb-2",children:[e.jsx("code",{children:"car:read"}),": View car details"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("code",{children:"car:write"}),": Modify car details"]})]}),e.jsx("p",{className:"mb-4",children:"Scopes are defined at the resource server level and can be associated with any resource. This allows consistent permission semantics across all car resources."}),e.jsx("h3",{className:"text-xl font-medium mt-6 mb-3",children:"Policies"}),e.jsx("p",{className:"mb-4",children:"Policies are the conditions that must be satisfied for access to be granted. Keycloak supports several policy types:"}),e.jsxs("ul",{className:"list-disc pl-6 mb-4",children:[e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Role Policy (RBAC):"})," Grant access based on realm or client roles"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"User Policy:"})," Grant access to specific users"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Attribute Policy (ABAC):"})," Evaluate custom attributes from the token or context"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"JavaScript Policy:"})," Custom logic using JavaScript"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Time Policy:"})," Temporal access restrictions"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Aggregated Policy:"})," Combine multiple policies with AND/OR logic"]})]}),e.jsx("p",{className:"mb-4",children:"For our implementation, we'll combine role-based and attribute-based policies to create sophisticated authorization rules."}),e.jsx("h3",{className:"text-xl font-medium mt-6 mb-3",children:"Permissions"}),e.jsx("p",{className:"mb-4",children:'Permissions bind resources and scopes to policies. They answer the question: "Under what policy conditions can a scope be performed on a resource?"'}),e.jsx("p",{className:"mb-4",children:"Keycloak supports two permission types:"}),e.jsxs("ul",{className:"list-disc pl-6 mb-4",children:[e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Resource-based permissions:"})," Apply to specific resources or resource types"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Scope-based permissions:"})," Apply to scopes across multiple resources"]})]}),e.jsx("h2",{className:"text-2xl font-medium mt-8 mb-4",children:"Technical Implementation"}),e.jsx("h3",{className:"text-xl font-medium mt-6 mb-3",children:"Step 1: Configure the Resource Server"}),e.jsx("p",{className:"mb-4",children:"First, create a client in Keycloak that represents your backend API:"}),e.jsx("pre",{className:"bg-gray-100 p-4 rounded-lg mb-4 overflow-x-auto",children:`{
  "clientId": "car-api",
  "protocol": "openid-connect",
  "publicClient": false,
  "authorizationServicesEnabled": true,
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false,
  "directAccessGrantsEnabled": false
}`}),e.jsxs("p",{className:"mb-4",children:["The ",e.jsx("code",{children:"serviceAccountsEnabled"})," flag is crucial—it allows your backend to authenticate with Keycloak to register resources dynamically using client credentials."]}),e.jsx("h3",{className:"text-xl font-medium mt-6 mb-3",children:"Step 2: Define Scopes"}),e.jsx("p",{className:"mb-4",children:"In the Keycloak admin console, navigate to your resource server's Authorization settings and define scopes:"}),e.jsxs("ul",{className:"list-disc pl-6 mb-4",children:[e.jsxs("li",{className:"mb-2",children:["Name: ",e.jsx("code",{children:"car:read"}),', Display Name: "Read Car"']}),e.jsxs("li",{className:"mb-2",children:["Name: ",e.jsx("code",{children:"car:write"}),', Display Name: "Write Car"']})]}),e.jsx("h3",{className:"text-xl font-medium mt-6 mb-3",children:"Step 3: Dynamic Resource Registration"}),e.jsx("p",{className:"mb-4",children:"When your server creates a new car, it must register the resource with Keycloak using the Protection API. Here's the flow:"}),e.jsx("pre",{className:"bg-gray-100 p-4 rounded-lg mb-4 overflow-x-auto text-sm",children:`import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;

import java.util.*;

public class KeycloakResourceManager {

    private final AuthzClient authzClient;

    public KeycloakResourceManager(String serverUrl, String realm,
                                   String clientId, String clientSecret) {
        Map<String, Object> credentials = new HashMap<>();
        credentials.put("secret", clientSecret);

        Configuration configuration = new Configuration(
            serverUrl,
            realm,
            clientId,
            credentials,
            null
        );

        this.authzClient = AuthzClient.create(configuration);
    }

    public String registerResource(String carId, String ownerId,
                                   Map<String, String> carAttributes) {
        ResourceRepresentation resource = new ResourceRepresentation();
        resource.setName("Car " + carId);
        resource.setType("urn:car-api:resources:car");
        resource.setUri("/car/" + carId);
        resource.setOwner(ownerId);
        resource.setOwnerManagedAccess(true); // Enable UMA

        // Define scopes for this resource
        Set<ScopeRepresentation> scopes = new HashSet<>();
        scopes.add(new ScopeRepresentation("car:read"));
        scopes.add(new ScopeRepresentation("car:write"));
        resource.setScopes(scopes);

        // Add custom attributes for ABAC policies
        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put("manufacturer",
            Collections.singletonList(carAttributes.get("manufacturer")));
        attributes.put("category",
            Collections.singletonList(carAttributes.get("category")));
        attributes.put("year",
            Collections.singletonList(String.valueOf(carAttributes.get("year"))));
        resource.setAttributes(attributes);

        // Register with Keycloak
        ResourceRepresentation created = authzClient
            .protection()
            .resource()
            .create(resource);

        return created.getId(); // Keycloak's internal resource ID
    }

    public void deleteResource(String resourceId) {
        authzClient.protection().resource().delete(resourceId);
    }
}`}),e.jsxs("p",{className:"mb-4",children:["The critical field here is ",e.jsx("code",{children:"setOwnerManagedAccess(true)"}),", which enables UMA for this resource, allowing the owner to manage permissions independently."]}),e.jsx("h3",{className:"text-xl font-medium mt-6 mb-3",children:"Step 4: Create Base Policies"}),e.jsx("p",{className:"mb-4",children:"Define policies that will be referenced by permissions. In the Keycloak admin console:"}),e.jsxs("p",{className:"mb-4",children:[e.jsx("strong",{children:"Admin Role Policy (RBAC)"}),":"]}),e.jsxs("ul",{className:"list-disc pl-6 mb-4",children:[e.jsx("li",{className:"mb-2",children:"Type: Role"}),e.jsxs("li",{className:"mb-2",children:["Name: ",e.jsx("code",{children:"admin-role-policy"})]}),e.jsxs("li",{className:"mb-2",children:["Realm roles: ",e.jsx("code",{children:"admin"})]}),e.jsx("li",{className:"mb-2",children:"Logic: Positive"})]}),e.jsxs("p",{className:"mb-4",children:[e.jsx("strong",{children:"Owner Policy (ABAC)"}),":"]}),e.jsxs("ul",{className:"list-disc pl-6 mb-4",children:[e.jsx("li",{className:"mb-2",children:"Type: JavaScript"}),e.jsxs("li",{className:"mb-2",children:["Name: ",e.jsx("code",{children:"resource-owner-policy"})]}),e.jsx("li",{className:"mb-2",children:"Code:"})]}),e.jsx("pre",{className:"bg-gray-100 p-4 rounded-lg mb-4 overflow-x-auto text-sm",children:`var context = $evaluation.getContext();
var identity = context.getIdentity();
var resource = $evaluation.getPermission().getResource();

if (resource.getOwner().equals(identity.getId())) {
    $evaluation.grant();
}`}),e.jsxs("p",{className:"mb-4",children:[e.jsx("strong",{children:"Premium User Read Policy (ABAC)"}),":"]}),e.jsxs("ul",{className:"list-disc pl-6 mb-4",children:[e.jsx("li",{className:"mb-2",children:"Type: Attribute"}),e.jsxs("li",{className:"mb-2",children:["Name: ",e.jsx("code",{children:"premium-user-read-policy"})]}),e.jsxs("li",{className:"mb-2",children:["Condition: User attribute ",e.jsx("code",{children:"subscription"})," equals ",e.jsx("code",{children:"premium"})]})]}),e.jsx("h3",{className:"text-xl font-medium mt-6 mb-3",children:"Step 5: Define Default Permissions"}),e.jsx("p",{className:"mb-4",children:"Create resource-based permissions that apply to all car resources:"}),e.jsxs("p",{className:"mb-4",children:[e.jsx("strong",{children:"Admin Full Access"}),":"]}),e.jsxs("ul",{className:"list-disc pl-6 mb-4",children:[e.jsxs("li",{className:"mb-2",children:["Name: ",e.jsx("code",{children:"admin-full-access-permission"})]}),e.jsxs("li",{className:"mb-2",children:["Resource Type: ",e.jsx("code",{children:"urn:car-api:resources:car"})]}),e.jsxs("li",{className:"mb-2",children:["Scopes: ",e.jsx("code",{children:"car:read"}),", ",e.jsx("code",{children:"car:write"})]}),e.jsxs("li",{className:"mb-2",children:["Policies: ",e.jsx("code",{children:"admin-role-policy"})]}),e.jsx("li",{className:"mb-2",children:"Decision Strategy: Unanimous"})]}),e.jsxs("p",{className:"mb-4",children:[e.jsx("strong",{children:"Owner Full Access"}),":"]}),e.jsxs("ul",{className:"list-disc pl-6 mb-4",children:[e.jsxs("li",{className:"mb-2",children:["Name: ",e.jsx("code",{children:"owner-full-access-permission"})]}),e.jsxs("li",{className:"mb-2",children:["Resource Type: ",e.jsx("code",{children:"urn:car-api:resources:car"})]}),e.jsxs("li",{className:"mb-2",children:["Scopes: ",e.jsx("code",{children:"car:read"}),", ",e.jsx("code",{children:"car:write"})]}),e.jsxs("li",{className:"mb-2",children:["Policies: ",e.jsx("code",{children:"resource-owner-policy"})]}),e.jsx("li",{className:"mb-2",children:"Decision Strategy: Unanimous"})]}),e.jsxs("p",{className:"mb-4",children:[e.jsx("strong",{children:"Premium Read Access"}),":"]}),e.jsxs("ul",{className:"list-disc pl-6 mb-4",children:[e.jsxs("li",{className:"mb-2",children:["Name: ",e.jsx("code",{children:"premium-read-permission"})]}),e.jsxs("li",{className:"mb-2",children:["Resource Type: ",e.jsx("code",{children:"urn:car-api:resources:car"})]}),e.jsxs("li",{className:"mb-2",children:["Scopes: ",e.jsx("code",{children:"car:read"})]}),e.jsxs("li",{className:"mb-2",children:["Policies: ",e.jsx("code",{children:"premium-user-read-policy"})]}),e.jsx("li",{className:"mb-2",children:"Decision Strategy: Affirmative"})]}),e.jsx("h3",{className:"text-xl font-medium mt-6 mb-3",children:"Step 6: Enforce Authorization in Your API"}),e.jsx("p",{className:"mb-4",children:"When a request arrives at your API, you must request an authorization decision from Keycloak:"}),e.jsx("pre",{className:"bg-gray-100 p-4 rounded-lg mb-4 overflow-x-auto text-sm",children:`import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.resource.AuthorizationResource;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;

@Path("/car")
public class CarResource {

    private final AuthzClient authzClient;

    public CarResource(AuthzClient authzClient) {
        this.authzClient = authzClient;
    }

    @GET
    @Path("/{carId}")
    @Produces("application/json")
    public Response getCar(@PathParam("carId") String carId,
                          @HeaderParam("Authorization") String authorizationHeader) {

        String accessToken = extractToken(authorizationHeader);

        // Check permission with Keycloak
        if (!checkPermission(accessToken, "/car/" + carId, "car:read")) {
            return Response.status(Response.Status.FORBIDDEN)
                .entity("Access denied")
                .build();
        }

        // Fetch and return car data
        Car car = fetchCarFromDatabase(carId);
        return Response.ok(car).build();
    }

    @PUT
    @Path("/{carId}")
    @Consumes("application/json")
    @Produces("application/json")
    public Response updateCar(@PathParam("carId") String carId,
                             @HeaderParam("Authorization") String authorizationHeader,
                             Car updatedCar) {

        String accessToken = extractToken(authorizationHeader);

        // Check permission with Keycloak
        if (!checkPermission(accessToken, "/car/" + carId, "car:write")) {
            return Response.status(Response.Status.FORBIDDEN)
                .entity("Access denied")
                .build();
        }

        // Update car data
        updateCarInDatabase(carId, updatedCar);
        return Response.ok().entity("{\\"status\\": \\"updated\\"}").build();
    }

    private boolean checkPermission(String accessToken, String resourceUri,
                                   String scope) {
        try {
            AuthorizationRequest request = new AuthorizationRequest();
            request.addPermission(resourceUri, scope);

            AuthorizationResponse response = authzClient
                .authorization(accessToken)
                .authorize(request);

            // If we get a response, permission is granted
            return response.getToken() != null;

        } catch (Exception e) {
            // Authorization denied or error occurred
            return false;
        }
    }

    private String extractToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        throw new WebApplicationException("Missing or invalid authorization header",
            Response.Status.UNAUTHORIZED);
    }
}`}),e.jsx("p",{className:"mb-4",children:"The authorization flow here uses the UMA grant type, which evaluates all policies and permissions associated with the requested resource and scope."}),e.jsx("h3",{className:"text-xl font-medium mt-6 mb-3",children:"Step 7: Leverage Keycloak's Built-in UMA Account Console"}),e.jsx("p",{className:"mb-4",children:"Keycloak provides a built-in Account Console with User-Managed Access capabilities that allows resource owners to manage permissions without any custom development. This is one of the most powerful features of Keycloak's UMA implementation."}),e.jsxs("p",{className:"mb-4",children:[e.jsx("strong",{children:"Enabling the Account Console"}),":"]}),e.jsx("p",{className:"mb-4",children:"The Account Console is available by default at:"}),e.jsx("pre",{className:"bg-gray-100 p-4 rounded-lg mb-4 overflow-x-auto",children:"https://<keycloak-server>/realms/<realm-name>/account"}),e.jsx("p",{className:"mb-4",children:`Once users log in to the Account Console, they can navigate to the "Resources" or "My Resources" section, where they'll see:`}),e.jsxs("ol",{className:"list-decimal pl-6 mb-4",children:[e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"All resources they own:"})," Every resource registered with ",e.jsx("code",{children:"ownerManagedAccess: true"})," and their user ID as owner"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Resource details:"})," Name, type, URI, and available scopes"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Current permissions:"})," List of users who have been granted access and their specific scopes"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Share functionality:"})," UI to grant new permissions to other users"]})]}),e.jsxs("p",{className:"mb-4",children:[e.jsx("strong",{children:"How it works"}),":"]}),e.jsx("p",{className:"mb-4",children:"When a resource owner wants to share access:"}),e.jsxs("ol",{className:"list-decimal pl-6 mb-4",children:[e.jsx("li",{className:"mb-2",children:"They navigate to their resource in the Account Console"}),e.jsx("li",{className:"mb-2",children:'Click "Share" or "Add Permission"'}),e.jsx("li",{className:"mb-2",children:"Enter the username or email of the user they want to grant access to"}),e.jsxs("li",{className:"mb-2",children:["Select which scopes to grant (e.g., ",e.jsx("code",{children:"car:read"}),", ",e.jsx("code",{children:"car:write"}),")"]}),e.jsx("li",{className:"mb-2",children:"Submit the permission"})]}),e.jsx("p",{className:"mb-4",children:"Behind the scenes, Keycloak creates a UMA permission ticket that binds the resource, the requester, and the granted scopes."}),e.jsxs("p",{className:"mb-4",children:[e.jsx("strong",{children:"Deep Linking from Your Application"}),":"]}),e.jsx("p",{className:"mb-4",children:"You can provide direct links from your application to the relevant sections of the Account Console:"}),e.jsx("pre",{className:"bg-gray-100 p-4 rounded-lg mb-4 overflow-x-auto text-sm",children:`public class AccountConsoleConfig {

    private final String keycloakUrl;
    private final String realm;

    public AccountConsoleConfig(String keycloakUrl, String realm) {
        this.keycloakUrl = keycloakUrl;
        this.realm = realm;
    }

    public String getAccountConsoleUrl() {
        return String.format("%s/realms/%s/account", keycloakUrl, realm);
    }

    public String getMyResourcesUrl() {
        return String.format("%s/realms/%s/account/#/resources", keycloakUrl, realm);
    }

    public String getResourceDetailUrl(String resourceId) {
        return String.format("%s/realms/%s/account/#/resources/%s",
            keycloakUrl, realm, resourceId);
    }
}`}),e.jsxs("p",{className:"mb-4",children:[e.jsx("strong",{children:"Benefits of Using the Built-in Account Console"}),":"]}),e.jsxs("ul",{className:"list-disc pl-6 mb-4",children:[e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Zero custom development:"})," No need to build UI for permission management"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Consistent UX:"})," Users get a familiar, well-tested interface"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Automatic updates:"})," New Keycloak features appear automatically"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Security:"})," All permission operations go through Keycloak's validated APIs"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Audit trail:"})," Keycloak logs all permission changes"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Multi-language support:"})," Account Console supports internationalization"]})]}),e.jsx("h2",{className:"text-2xl font-medium mt-8 mb-4",children:"Decision Strategies and Policy Composition"}),e.jsx("p",{className:"mb-4",children:"When multiple policies apply to a permission, Keycloak uses a decision strategy:"}),e.jsxs("ul",{className:"list-disc pl-6 mb-4",children:[e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Unanimous:"})," All policies must grant access"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Affirmative:"})," At least one policy must grant access"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Consensus:"})," Majority of policies must grant access"]})]}),e.jsx("p",{className:"mb-4",children:"You can create complex authorization logic using aggregated policies. For example:"}),e.jsx("pre",{className:"bg-gray-100 p-4 rounded-lg mb-4 overflow-x-auto text-sm",children:`Permission: "Sensitive Car Write"
├─ Aggregated Policy (AND)
│  ├─ Owner Policy (must be owner)
│  └─ Time Policy (only business hours)
└─ Decision Strategy: Unanimous`}),e.jsx("h2",{className:"text-2xl font-medium mt-8 mb-4",children:"Performance Considerations"}),e.jsx("p",{className:"mb-4",children:"Dynamic resource registration at scale requires careful consideration:"}),e.jsxs("ol",{className:"list-decimal pl-6 mb-4",children:[e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Caching:"})," Cache authorization decisions at the API layer with short TTLs"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Batch Operations:"})," Register resources in batches when possible"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Resource Cleanup:"})," Implement lifecycle management to delete resources from Keycloak when cars are deleted"]}),e.jsxs("li",{className:"mb-2",children:[e.jsx("strong",{children:"Database Indexing:"})," Ensure your application maintains a mapping between business IDs and Keycloak resource IDs"]})]}),e.jsx("pre",{className:"bg-gray-100 p-4 rounded-lg mb-4 overflow-x-auto text-sm",children:`public class ResourceLifecycleManager {

    private final KeycloakResourceManager resourceManager;
    private final CarRepository carRepository;

    public void createCar(Car car, String ownerId) {
        // 1. Save to database
        carRepository.save(car);

        // 2. Register with Keycloak
        Map<String, String> attributes = new HashMap<>();
        attributes.put("manufacturer", car.getManufacturer());
        attributes.put("category", car.getCategory());
        attributes.put("year", String.valueOf(car.getYear()));

        String keycloakResourceId = resourceManager.registerResource(
            car.getId(),
            ownerId,
            attributes
        );

        // 3. Store mapping
        carRepository.updateKeycloakResourceId(car.getId(), keycloakResourceId);
    }

    public void deleteCar(String carId) {
        // 1. Get Keycloak resource ID
        String keycloakResourceId = carRepository.getKeycloakResourceId(carId);

        // 2. Delete from Keycloak
        if (keycloakResourceId != null) {
            resourceManager.deleteResource(keycloakResourceId);
        }

        // 3. Delete from database
        carRepository.delete(carId);
    }
}`}),e.jsx("h2",{className:"text-2xl font-medium mt-8 mb-4",children:"Conclusion"}),e.jsx("p",{className:"mb-4",children:"Keycloak's UMA implementation provides enterprise-grade fine-grained authorization for dynamic resource scenarios. By combining resource server configuration, dynamic resource registration, RBAC and ABAC policies, and Keycloak's built-in Account Console, you can build systems where users safely manage their own access control policies without requiring custom UI development."}),e.jsx("p",{className:"mb-4",children:"The architecture we've outlined separates concerns effectively: your application logic focuses on business operations, while Keycloak handles the complex authorization decisions using a standardized, auditable framework. The built-in Account Console eliminates the need for custom permission management UI while still allowing programmatic access when needed."}),e.jsx("p",{className:"mb-4",children:"This approach scales from hundreds to millions of resources while maintaining consistent security policies. For production deployments, consider implementing comprehensive audit logging, monitoring policy evaluation latency, and establishing governance processes around policy creation and modification. The flexibility of Keycloak's authorization services means you can start simple and evolve your authorization model as requirements grow more sophisticated."}),e.jsxs("div",{className:"bg-gray-100 p-6 rounded-lg mt-8",children:[e.jsx("h3",{className:"text-xl font-medium mb-3",children:"Want to Learn More?"}),e.jsx("p",{className:"mb-4",children:"Explore Keycloak's comprehensive documentation on authorization services and UMA implementation to dive deeper into fine-grained access control for your applications."}),e.jsx("a",{href:"https://www.keycloak.org/docs/latest/authorization_services/",className:"inline-block bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700",target:"_blank",rel:"noopener noreferrer",children:"Read Keycloak Documentation"})]})]})]}),c=Object.freeze(Object.defineProperty({__proto__:null,default:o},Symbol.toStringTag,{value:"Module"})),u={hasServerOnlyHook:{type:"computed",definedAtData:null,valueSerialized:{type:"js-serialized",value:!1}},isClientRuntimeLoaded:{type:"computed",definedAtData:null,valueSerialized:{type:"js-serialized",value:!0}},onBeforeRenderEnv:{type:"computed",definedAtData:null,valueSerialized:{type:"js-serialized",value:null}},dataEnv:{type:"computed",definedAtData:null,valueSerialized:{type:"js-serialized",value:null}},guardEnv:{type:"computed",definedAtData:null,valueSerialized:{type:"js-serialized",value:null}},onRenderClient:{type:"standard",definedAtData:{filePathToShowToUser:"vike-react/__internal/integration/onRenderClient",fileExportPathToShowToUser:[]},valueSerialized:{type:"pointer-import",value:t}},onPageTransitionStart:{type:"standard",definedAtData:{filePathToShowToUser:"/pages/+onPageTransitionStart.ts",fileExportPathToShowToUser:[]},valueSerialized:{type:"plus-file",exportValues:i}},onPageTransitionEnd:{type:"standard",definedAtData:{filePathToShowToUser:"/pages/+onPageTransitionEnd.ts",fileExportPathToShowToUser:[]},valueSerialized:{type:"plus-file",exportValues:a}},Page:{type:"standard",definedAtData:{filePathToShowToUser:"/pages/blog/keycloak-uma/+Page.tsx",fileExportPathToShowToUser:[]},valueSerialized:{type:"plus-file",exportValues:c}},hydrationCanBeAborted:{type:"standard",definedAtData:{filePathToShowToUser:"vike-react/config",fileExportPathToShowToUser:["default","hydrationCanBeAborted"]},valueSerialized:{type:"js-serialized",value:!0}},Layout:{type:"cumulative",definedAtData:[{filePathToShowToUser:"/pages/+Layout.tsx",fileExportPathToShowToUser:[]}],valueSerialized:[{type:"plus-file",exportValues:r}]},title:{type:"standard",definedAtData:{filePathToShowToUser:"/pages/+config.ts",fileExportPathToShowToUser:["default","title"]},valueSerialized:{type:"js-serialized",value:"Hilberg IT Beratung - Software Developers & Architects"}},lang:{type:"standard",definedAtData:{filePathToShowToUser:"/pages/+config.ts",fileExportPathToShowToUser:["default","lang"]},valueSerialized:{type:"js-serialized",value:"de"}},Loading:{type:"standard",definedAtData:{filePathToShowToUser:"vike-react/__internal/integration/Loading",fileExportPathToShowToUser:[]},valueSerialized:{type:"pointer-import",value:s}}};export{u as configValuesSerialized};
