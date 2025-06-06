---
title: "API Security Best Practices for Cloud-Native Applications"
date: 2019-08-17T10:00:00-07:00
draft: false
categories: ["Security", "API Development"]
tags:
- Security
- API Security
- OAuth
- JWT
- Rate Limiting
- TypeScript
- AWS
series: "Security in Cloud-Native Applications"
---

Application Programming Interfaces (APIs) have become the fundamental building blocks of cloud-native applications, enabling microservices to communicate and external systems to integrate with internal services. However, this increased connectivity and exposure also creates significant security challenges that must be addressed through comprehensive API security strategies. Modern cloud-native applications often expose dozens or hundreds of APIs, each representing a potential attack vector that requires careful security consideration.

The security of APIs in cloud-native environments is particularly complex because these interfaces must balance accessibility with protection, enabling legitimate users and services to interact efficiently while preventing unauthorized access and malicious activities. This challenge is compounded by the dynamic nature of cloud-native deployments, where API endpoints may be created, modified, or destroyed frequently as applications scale and evolve.

## API Gateway Security Architecture

A robust API gateway serves as the primary security enforcement point for cloud-native applications, providing centralized control over authentication, authorization, rate limiting, and other security policies. The gateway architecture must be designed to handle high-throughput scenarios while maintaining low latency and providing comprehensive security controls that can adapt to changing threat landscapes.

Modern API gateways must implement multiple layers of security controls, from basic authentication and authorization to advanced threat detection and response capabilities. The gateway architecture should support policy-driven security configurations that can be applied consistently across all APIs while allowing for service-specific customizations when necessary.

{{< plantuml >}}
@startuml
!define RECTANGLE class

RECTANGLE "API Gateway" as Gateway {
  +authenticateRequest()
  +authorizeAccess()
  +validateInput()
  +enforceRateLimit()
  +detectThreats()
}

RECTANGLE "Authentication Service" as Auth {
  +validateToken()
  +refreshCredentials()
  +revokeAccess()
  +auditLogin()
}

RECTANGLE "Authorization Engine" as Authz {
  +evaluatePolicy()
  +checkPermissions()
  +applyConstraints()
  +logDecision()
}

RECTANGLE "Rate Limiter" as RateLimit {
  +checkQuota()
  +updateCounters()
  +enforceThrottling()
  +handleBurst()
}

RECTANGLE "Security Scanner" as Scanner {
  +scanPayload()
  +detectInjection()
  +validateSignature()
  +checkReputation()
}

RECTANGLE "Threat Detection" as ThreatDetect {
  +analyzePattern()
  +correlateEvents()
  +assessRisk()
  +triggerResponse()
}

RECTANGLE "Backend Service" as Backend {
  +processRequest()
  +validateBusiness()
  +executeLogic()
  +returnResponse()
}

RECTANGLE "Audit Logger" as Audit {
  +logRequest()
  +trackAccess()
  +recordAnomaly()
  +generateReport()
}

Gateway --> Auth : validate credentials
Gateway --> Authz : check permissions
Gateway --> RateLimit : enforce limits
Gateway --> Scanner : scan request
Gateway --> ThreatDetect : analyze behavior
Gateway --> Backend : forward request
Gateway --> Audit : log activity

Auth --> Audit : authentication events
Authz --> Audit : authorization decisions
ThreatDetect --> Audit : security alerts
@enduml
{{< /plantuml >}}

```typescript
// Comprehensive API Gateway security implementation
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verify, sign } from 'jsonwebtoken';
import { RateLimiterRedis } from 'rate-limiter-flexible';
import { createHash, createHmac } from 'crypto';

interface SecurityConfig {
  authentication: AuthenticationConfig;
  authorization: AuthorizationConfig;
  rateLimiting: RateLimitingConfig;
  inputValidation: InputValidationConfig;
  threatDetection: ThreatDetectionConfig;
  auditLogging: AuditLoggingConfig;
}

interface AuthenticationConfig {
  enabled: boolean;
  methods: AuthMethod[];
  tokenValidation: TokenValidationConfig;
  sessionManagement: SessionConfig;
}

interface AuthorizationConfig {
  enabled: boolean;
  engine: AuthorizationEngine;
  policies: SecurityPolicy[];
  defaultAction: PolicyAction;
}

interface RateLimitingConfig {
  enabled: boolean;
  limits: RateLimit[];
  burstAllowance: number;
  slidingWindow: boolean;
  keyGenerators: KeyGenerator[];
}

interface ThreatDetectionConfig {
  enabled: boolean;
  patterns: ThreatPattern[];
  mlModels: MLModelConfig[];
  realTimeAnalysis: boolean;
  responseActions: ResponseAction[];
}

enum AuthMethod {
  BEARER_TOKEN = 'BEARER_TOKEN',
  API_KEY = 'API_KEY',
  MUTUAL_TLS = 'MUTUAL_TLS',
  OAUTH2 = 'OAUTH2',
  JWT = 'JWT'
}

enum PolicyAction {
  ALLOW = 'ALLOW',
  DENY = 'DENY',
  AUDIT = 'AUDIT',
  CHALLENGE = 'CHALLENGE'
}

export class SecureAPIGateway {
  private securityConfig: SecurityConfig;
  private rateLimiter: RateLimiterRedis;
  private threatDetector: ThreatDetector;
  private auditLogger: AuditLogger;
  private authenticationCache: Map<string, CachedAuthResult> = new Map();

  constructor(config: SecurityConfig) {
    this.securityConfig = config;
    this.rateLimiter = new RateLimiterRedis({
      storeClient: this.createRedisClient(),
      keyPrefix: 'api_rate_limit',
      points: config.rateLimiting.limits[0]?.maxRequests || 1000,
      duration: config.rateLimiting.limits[0]?.windowSeconds || 3600
    });
    
    this.threatDetector = new ThreatDetector(config.threatDetection);
    this.auditLogger = new AuditLogger(config.auditLogging);
    
    this.initializeSecurityMiddleware();
  }

  async handleRequest(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
    const requestId = this.generateRequestId();
    const startTime = Date.now();
    
    try {
      // Create request context
      const requestContext = await this.createRequestContext(event, requestId);
      
      // Execute security pipeline
      const securityResult = await this.executeSecurityPipeline(requestContext);
      
      if (securityResult.action === PolicyAction.DENY) {
        return this.createSecurityResponse(securityResult, requestId);
      }
      
      // Forward to backend service
      const backendResponse = await this.forwardToBackend(requestContext, securityResult);
      
      // Apply response security measures
      const secureResponse = await this.secureResponse(backendResponse, requestContext);
      
      // Log successful request
      await this.auditLogger.logRequest(requestContext, securityResult, Date.now() - startTime);
      
      return secureResponse;
      
    } catch (error) {
      // Log error and return secure error response
      await this.auditLogger.logError(requestId, error);
      return this.createErrorResponse(error, requestId);
    }
  }

  private async executeSecurityPipeline(context: RequestContext): Promise<SecurityResult> {
    const pipeline = [
      this.authenticateRequest.bind(this),
      this.authorizeRequest.bind(this),
      this.validateInput.bind(this),
      this.checkRateLimit.bind(this),
      this.detectThreats.bind(this),
      this.applySecurityHeaders.bind(this)
    ];
    
    let result: SecurityResult = {
      action: PolicyAction.ALLOW,
      context,
      securityHeaders: {},
      transformations: []
    };
    
    for (const step of pipeline) {
      result = await step(result);
      
      if (result.action === PolicyAction.DENY) {
        break;
      }
    }
    
    return result;
  }

  private async authenticateRequest(securityResult: SecurityResult): Promise<SecurityResult> {
    if (!this.securityConfig.authentication.enabled) {
      return securityResult;
    }
    
    const context = securityResult.context;
    const authHeader = context.headers.authorization;
    
    if (!authHeader) {
      return {
        ...securityResult,
        action: PolicyAction.DENY,
        reason: 'Missing authorization header'
      };
    }
    
    // Check cache first
    const cacheKey = this.generateAuthCacheKey(authHeader);
    const cached = this.authenticationCache.get(cacheKey);
    
    if (cached && !this.isAuthCacheExpired(cached)) {
      return {
        ...securityResult,
        authenticatedUser: cached.user,
        authenticationMethod: cached.method
      };
    }
    
    // Perform authentication based on method
    const authResult = await this.performAuthentication(authHeader, context);
    
    if (!authResult.success) {
      return {
        ...securityResult,
        action: PolicyAction.DENY,
        reason: authResult.reason
      };
    }
    
    // Cache successful authentication
    this.cacheAuthResult(cacheKey, authResult);
    
    return {
      ...securityResult,
      authenticatedUser: authResult.user,
      authenticationMethod: authResult.method
    };
  }

  private async performAuthentication(authHeader: string, context: RequestContext): Promise<AuthenticationResult> {
    const [method, credentials] = authHeader.split(' ');
    
    switch (method.toUpperCase()) {
      case 'BEARER':
        return await this.authenticateBearer(credentials, context);
      
      case 'APIKEY':
        return await this.authenticateApiKey(credentials, context);
      
      default:
        return {
          success: false,
          reason: `Unsupported authentication method: ${method}`
        };
    }
  }

  private async authenticateBearer(token: string, context: RequestContext): Promise<AuthenticationResult> {
    try {
      // Validate JWT token
      const decoded = verify(token, this.getJWTSecret(), {
        algorithms: ['HS256', 'RS256'],
        issuer: this.securityConfig.authentication.tokenValidation.issuer,
        audience: this.securityConfig.authentication.tokenValidation.audience
      });
      
      if (typeof decoded === 'object' && decoded !== null) {
        // Additional security checks
        const securityChecks = await this.performTokenSecurityChecks(decoded, context);
        
        if (!securityChecks.passed) {
          return {
            success: false,
            reason: securityChecks.reason
          };
        }
        
        return {
          success: true,
          user: {
            id: decoded.sub as string,
            email: decoded.email as string,
            roles: decoded.roles as string[] || [],
            scope: decoded.scope as string
          },
          method: AuthMethod.JWT
        };
      }
      
      return {
        success: false,
        reason: 'Invalid token payload'
      };
      
    } catch (error) {
      return {
        success: false,
        reason: `Token validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  private async authenticateApiKey(apiKey: string, context: RequestContext): Promise<AuthenticationResult> {
    // Validate API key format
    if (!this.validateApiKeyFormat(apiKey)) {
      return {
        success: false,
        reason: 'Invalid API key format'
      };
    }
    
    // Look up API key in secure store
    const keyInfo = await this.lookupApiKey(apiKey);
    
    if (!keyInfo) {
      return {
        success: false,
        reason: 'API key not found'
      };
    }
    
    // Check if key is active and not expired
    if (!keyInfo.isActive || (keyInfo.expiresAt && keyInfo.expiresAt <= new Date())) {
      return {
        success: false,
        reason: 'API key is inactive or expired'
      };
    }
    
    // Check usage limits
    const usageCheck = await this.checkApiKeyUsage(apiKey, keyInfo);
    if (!usageCheck.withinLimits) {
      return {
        success: false,
        reason: 'API key usage limit exceeded'
      };
    }
    
    return {
      success: true,
      user: {
        id: keyInfo.userId,
        email: keyInfo.userEmail,
        roles: keyInfo.roles,
        scope: keyInfo.scope
      },
      method: AuthMethod.API_KEY
    };
  }

  private async authorizeRequest(securityResult: SecurityResult): Promise<SecurityResult> {
    if (!this.securityConfig.authorization.enabled || !securityResult.authenticatedUser) {
      return securityResult;
    }
    
    const context = securityResult.context;
    const user = securityResult.authenticatedUser;
    
    // Build authorization request
    const authzRequest = {
      subject: {
        id: user.id,
        roles: user.roles,
        attributes: await this.getUserAttributes(user.id)
      },
      resource: {
        path: context.path,
        method: context.httpMethod,
        service: context.service
      },
      action: this.mapHttpMethodToAction(context.httpMethod),
      environment: {
        ip: context.sourceIP,
        userAgent: context.userAgent,
        timestamp: new Date()
      }
    };
    
    // Evaluate authorization policies
    const authzResult = await this.evaluateAuthorizationPolicies(authzRequest);
    
    if (authzResult.decision === PolicyAction.DENY) {
      return {
        ...securityResult,
        action: PolicyAction.DENY,
        reason: authzResult.reason
      };
    }
    
    return {
      ...securityResult,
      authorizationResult: authzResult
    };
  }

  private async validateInput(securityResult: SecurityResult): Promise<SecurityResult> {
    if (!this.securityConfig.inputValidation.enabled) {
      return securityResult;
    }
    
    const context = securityResult.context;
    const validationRules = this.getValidationRules(context.path, context.httpMethod);
    
    // Validate headers
    const headerValidation = await this.validateHeaders(context.headers, validationRules.headers);
    if (!headerValidation.isValid) {
      return {
        ...securityResult,
        action: PolicyAction.DENY,
        reason: `Header validation failed: ${headerValidation.errors.join(', ')}`
      };
    }
    
    // Validate query parameters
    const queryValidation = await this.validateQueryParameters(context.queryStringParameters, validationRules.queryParams);
    if (!queryValidation.isValid) {
      return {
        ...securityResult,
        action: PolicyAction.DENY,
        reason: `Query parameter validation failed: ${queryValidation.errors.join(', ')}`
      };
    }
    
    // Validate request body
    if (context.body) {
      const bodyValidation = await this.validateRequestBody(context.body, validationRules.body);
      if (!bodyValidation.isValid) {
        return {
          ...securityResult,
          action: PolicyAction.DENY,
          reason: `Body validation failed: ${bodyValidation.errors.join(', ')}`
        };
      }
    }
    
    // Check for injection attacks
    const injectionCheck = await this.checkForInjectionAttacks(context);
    if (injectionCheck.detected) {
      return {
        ...securityResult,
        action: PolicyAction.DENY,
        reason: `Potential injection attack detected: ${injectionCheck.type}`
      };
    }
    
    return securityResult;
  }

  private async checkRateLimit(securityResult: SecurityResult): Promise<SecurityResult> {
    if (!this.securityConfig.rateLimiting.enabled) {
      return securityResult;
    }
    
    const context = securityResult.context;
    const rateLimitKey = this.generateRateLimitKey(context, securityResult.authenticatedUser);
    
    try {
      await this.rateLimiter.consume(rateLimitKey);
      return securityResult;
    } catch (rejRes) {
      const retryAfter = Math.round(rejRes.msBeforeNext / 1000) || 1;
      
      return {
        ...securityResult,
        action: PolicyAction.DENY,
        reason: 'Rate limit exceeded',
        headers: {
          'Retry-After': retryAfter.toString(),
          'X-RateLimit-Limit': this.securityConfig.rateLimiting.limits[0]?.maxRequests?.toString() || '1000',
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': new Date(Date.now() + rejRes.msBeforeNext).toISOString()
        }
      };
    }
  }

  private async detectThreats(securityResult: SecurityResult): Promise<SecurityResult> {
    if (!this.securityConfig.threatDetection.enabled) {
      return securityResult;
    }
    
    const context = securityResult.context;
    
    // Analyze request patterns
    const threatAnalysis = await this.threatDetector.analyzeRequest({
      ip: context.sourceIP,
      userAgent: context.userAgent,
      path: context.path,
      method: context.httpMethod,
      headers: context.headers,
      body: context.body,
      timestamp: new Date()
    });
    
    if (threatAnalysis.riskScore > this.securityConfig.threatDetection.riskThreshold) {
      // Determine response action based on risk level
      const responseAction = this.determineResponseAction(threatAnalysis.riskScore);
      
      if (responseAction === PolicyAction.DENY) {
        return {
          ...securityResult,
          action: PolicyAction.DENY,
          reason: `High risk request detected: ${threatAnalysis.threats.join(', ')}`
        };
      }
    }
    
    return {
      ...securityResult,
      threatAnalysis
    };
  }

  private async checkForInjectionAttacks(context: RequestContext): Promise<InjectionCheckResult> {
    const injectionPatterns = [
      // SQL Injection patterns
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/i,
      /('|(\\x27)|(\\x2D)|(;)|(\\x00)|(\\n)|(\\r)|(\\x1a))/i,
      
      // NoSQL Injection patterns
      /(\$where|\$ne|\$in|\$nin|\$exists|\$regex)/i,
      
      // XSS patterns
      /(<script|javascript:|vbscript:|onload=|onerror=|onclick=)/i,
      
      // Command injection patterns
      /(;|\|&|&&|\|\||`|\$\(|\${)/,
      
      // LDAP injection patterns
      /(\*|\)|\(|\\|\||&)/,
      
      // XML injection patterns
      /(<!DOCTYPE|<!ENTITY|SYSTEM|PUBLIC)/i
    ];
    
    const checkString = [
      context.path,
      JSON.stringify(context.queryStringParameters || {}),
      context.body || ''
    ].join(' ');
    
    for (const pattern of injectionPatterns) {
      if (pattern.test(checkString)) {
        return {
          detected: true,
          type: this.identifyInjectionType(pattern),
          pattern: pattern.source
        };
      }
    }
    
    return {
      detected: false
    };
  }

  private generateRateLimitKey(context: RequestContext, user?: AuthenticatedUser): string {
    const keyComponents = [];
    
    // Include user ID if authenticated
    if (user) {
      keyComponents.push(`user:${user.id}`);
    } else {
      keyComponents.push(`ip:${context.sourceIP}`);
    }
    
    // Include API endpoint
    keyComponents.push(`endpoint:${context.path}`);
    
    // Include method
    keyComponents.push(`method:${context.httpMethod}`);
    
    return keyComponents.join(':');
  }

  private async secureResponse(response: any, context: RequestContext): Promise<APIGatewayProxyResult> {
    const secureHeaders = {
      'Content-Security-Policy': "default-src 'self'",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    };
    
    // Remove sensitive headers
    const filteredHeaders = this.filterSensitiveHeaders(response.headers || {});
    
    return {
      statusCode: response.statusCode || 200,
      headers: {
        ...filteredHeaders,
        ...secureHeaders
      },
      body: response.body,
      isBase64Encoded: response.isBase64Encoded || false
    };
  }

  private createSecurityResponse(securityResult: SecurityResult, requestId: string): APIGatewayProxyResult {
    const statusCode = this.getStatusCodeForSecurityAction(securityResult.action, securityResult.reason);
    
    return {
      statusCode,
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': requestId,
        ...securityResult.headers
      },
      body: JSON.stringify({
        error: 'Security validation failed',
        message: securityResult.reason,
        requestId
      })
    };
  }

  private getStatusCodeForSecurityAction(action: PolicyAction, reason?: string): number {
    switch (action) {
      case PolicyAction.DENY:
        if (reason?.includes('authentication')) return 401;
        if (reason?.includes('authorization')) return 403;
        if (reason?.includes('rate limit')) return 429;
        if (reason?.includes('validation')) return 400;
        return 403;
      
      default:
        return 200;
    }
  }
}
```

## OAuth 2.0 and OpenID Connect Integration

Modern API security heavily relies on OAuth 2.0 and OpenID Connect protocols to provide secure, standardized authentication and authorization mechanisms. These protocols enable secure delegation of access rights while maintaining separation of concerns between authentication providers and resource servers. Implementing these protocols correctly requires understanding their nuances and potential security vulnerabilities.

The integration of OAuth 2.0 and OpenID Connect in cloud-native applications must address challenges such as token lifecycle management, scope validation, and the secure handling of refresh tokens. The implementation must also consider the various OAuth 2.0 flows and select the appropriate flow based on the client type and security requirements.

```typescript
// Comprehensive OAuth 2.0 and OpenID Connect implementation
interface OAuthConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string[];
  pkceEnabled: boolean;
  tokenEndpoint: string;
  authorizationEndpoint: string;
  jwksUri: string;
  userInfoEndpoint: string;
}

interface TokenResponse {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  tokenType: string;
  expiresIn: number;
  scope: string;
}

interface UserInfo {
  sub: string;
  name?: string;
  email?: string;
  emailVerified?: boolean;
  picture?: string;
  roles?: string[];
  permissions?: string[];
}

export class OAuthSecurityProvider {
  private config: OAuthConfig;
  private jwksClient: any;
  private tokenCache: Map<string, CachedToken> = new Map();
  
  constructor(config: OAuthConfig) {
    this.config = config;
    this.jwksClient = this.initializeJWKSClient();
    this.startTokenCleanup();
  }

  async initiateAuthorizationFlow(
    state: string,
    codeChallenge?: string,
    codeChallengeMethod?: string
  ): Promise<string> {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes.join(' '),
      state
    });

    // Add PKCE parameters if enabled
    if (this.config.pkceEnabled && codeChallenge) {
      params.append('code_challenge', codeChallenge);
      params.append('code_challenge_method', codeChallengeMethod || 'S256');
    }

    return `${this.config.authorizationEndpoint}?${params.toString()}`;
  }

  async exchangeCodeForTokens(
    authorizationCode: string,
    state: string,
    codeVerifier?: string
  ): Promise<TokenResponse> {
    // Validate state parameter to prevent CSRF attacks
    if (!this.validateState(state)) {
      throw new Error('Invalid state parameter');
    }

    const tokenRequest = {
      grant_type: 'authorization_code',
      code: authorizationCode,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret
    };

    // Add PKCE code verifier if enabled
    if (this.config.pkceEnabled && codeVerifier) {
      (tokenRequest as any).code_verifier = codeVerifier;
    }

    try {
      const response = await this.makeTokenRequest(tokenRequest);
      
      // Validate tokens
      await this.validateTokenResponse(response);
      
      // Cache tokens for future use
      if (response.accessToken) {
        await this.cacheToken(response.accessToken, response);
      }
      
      return response;
      
    } catch (error) {
      throw new Error(`Token exchange failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async validateAccessToken(accessToken: string): Promise<TokenValidationResult> {
    try {
      // Check cache first
      const cached = this.tokenCache.get(accessToken);
      if (cached && !this.isTokenExpired(cached)) {
        return {
          isValid: true,
          claims: cached.claims,
          scopes: cached.scopes
        };
      }

      // Validate token signature and claims
      const claims = await this.verifyJWT(accessToken);
      
      // Validate token claims
      const claimsValidation = await this.validateTokenClaims(claims);
      if (!claimsValidation.isValid) {
        return {
          isValid: false,
          reason: claimsValidation.reason
        };
      }

      // Extract scopes
      const scopes = this.extractScopes(claims);
      
      // Cache validated token
      await this.cacheToken(accessToken, {
        accessToken,
        tokenType: 'Bearer',
        expiresIn: claims.exp - Math.floor(Date.now() / 1000),
        scope: scopes.join(' ')
      });

      return {
        isValid: true,
        claims,
        scopes
      };

    } catch (error) {
      return {
        isValid: false,
        reason: `Token validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  async refreshTokens(refreshToken: string): Promise<TokenResponse> {
    const refreshRequest = {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret
    };

    try {
      const response = await this.makeTokenRequest(refreshRequest);
      
      // Validate new tokens
      await this.validateTokenResponse(response);
      
      // Invalidate old tokens from cache
      this.invalidateTokensForRefresh(refreshToken);
      
      // Cache new tokens
      if (response.accessToken) {
        await this.cacheToken(response.accessToken, response);
      }
      
      return response;
      
    } catch (error) {
      throw new Error(`Token refresh failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getUserInfo(accessToken: string): Promise<UserInfo> {
    // Validate access token first
    const tokenValidation = await this.validateAccessToken(accessToken);
    if (!tokenValidation.isValid) {
      throw new Error('Invalid access token');
    }

    // Check if token has required scope for user info
    if (!tokenValidation.scopes?.includes('openid')) {
      throw new Error('Token does not have required scope for user info');
    }

    try {
      const response = await fetch(this.config.userInfoEndpoint, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`UserInfo request failed: ${response.status} ${response.statusText}`);
      }

      const userInfo = await response.json();
      
      // Validate user info response
      await this.validateUserInfo(userInfo, tokenValidation.claims?.sub);
      
      return userInfo;
      
    } catch (error) {
      throw new Error(`Failed to retrieve user info: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async revokeToken(token: string, tokenTypeHint?: 'access_token' | 'refresh_token'): Promise<void> {
    const revokeRequest = {
      token,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret
    };

    if (tokenTypeHint) {
      (revokeRequest as any).token_type_hint = tokenTypeHint;
    }

    try {
      const response = await fetch(this.config.tokenEndpoint.replace('/token', '/revoke'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams(revokeRequest).toString()
      });

      if (!response.ok) {
        throw new Error(`Token revocation failed: ${response.status} ${response.statusText}`);
      }

      // Remove from cache
      this.tokenCache.delete(token);
      
    } catch (error) {
      throw new Error(`Token revocation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async verifyJWT(token: string): Promise<any> {
    return new Promise((resolve, reject) => {
      verify(token, this.getSigningKey.bind(this), {
        algorithms: ['RS256', 'ES256'],
        issuer: this.config.issuer,
        audience: this.config.clientId
      }, (err, decoded) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(decoded);
      });
    });
  }

  private async getSigningKey(header: any, callback: any): Promise<void> {
    try {
      const key = await this.jwksClient.getSigningKey(header.kid);
      const signingKey = key.getPublicKey();
      callback(null, signingKey);
    } catch (error) {
      callback(error);
    }
  }

  private async validateTokenClaims(claims: any): Promise<ValidationResult> {
    // Check expiration
    if (claims.exp && claims.exp <= Math.floor(Date.now() / 1000)) {
      return {
        isValid: false,
        reason: 'Token has expired'
      };
    }

    // Check not before
    if (claims.nbf && claims.nbf > Math.floor(Date.now() / 1000)) {
      return {
        isValid: false,
        reason: 'Token not yet valid'
      };
    }

    // Check issuer
    if (claims.iss !== this.config.issuer) {
      return {
        isValid: false,
        reason: 'Invalid issuer'
      };
    }

    // Check audience
    if (Array.isArray(claims.aud)) {
      if (!claims.aud.includes(this.config.clientId)) {
        return {
          isValid: false,
          reason: 'Invalid audience'
        };
      }
    } else if (claims.aud !== this.config.clientId) {
      return {
        isValid: false,
        reason: 'Invalid audience'
      };
    }

    // Validate scope if present
    if (claims.scope) {
      const tokenScopes = claims.scope.split(' ');
      const hasValidScope = this.config.scopes.some(scope => tokenScopes.includes(scope));
      if (!hasValidScope) {
        return {
          isValid: false,
          reason: 'Invalid scope'
        };
      }
    }

    return {
      isValid: true
    };
  }

  private extractScopes(claims: any): string[] {
    if (claims.scope) {
      return claims.scope.split(' ');
    }
    if (claims.scp) {
      return Array.isArray(claims.scp) ? claims.scp : [claims.scp];
    }
    return [];
  }

  private async validateUserInfo(userInfo: any, expectedSub?: string): Promise<void> {
    // Validate subject matches token
    if (expectedSub && userInfo.sub !== expectedSub) {
      throw new Error('UserInfo subject does not match token subject');
    }

    // Validate required fields
    if (!userInfo.sub) {
      throw new Error('UserInfo missing required subject field');
    }

    // Validate email if present
    if (userInfo.email && !this.isValidEmail(userInfo.email)) {
      throw new Error('UserInfo contains invalid email address');
    }
  }

  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  private validateState(state: string): boolean {
    // Implement state validation logic
    // This should verify that the state parameter matches what was sent
    // and includes CSRF protection
    return true; // Simplified for example
  }

  async validateScopes(requiredScopes: string[], tokenScopes: string[]): Promise<boolean> {
    return requiredScopes.every(scope => tokenScopes.includes(scope));
  }

  async introspectToken(token: string): Promise<TokenIntrospectionResult> {
    const introspectRequest = {
      token,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret
    };

    try {
      const response = await fetch(this.config.tokenEndpoint.replace('/token', '/introspect'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams(introspectRequest).toString()
      });

      if (!response.ok) {
        throw new Error(`Token introspection failed: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      
      return {
        active: result.active,
        scope: result.scope,
        clientId: result.client_id,
        username: result.username,
        tokenType: result.token_type,
        exp: result.exp,
        iat: result.iat,
        sub: result.sub,
        aud: result.aud,
        iss: result.iss
      };
      
    } catch (error) {
      throw new Error(`Token introspection failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private startTokenCleanup(): void {
    // Clean up expired tokens every 5 minutes
    setInterval(() => {
      const now = Date.now();
      for (const [token, cached] of this.tokenCache.entries()) {
        if (this.isTokenExpired(cached)) {
          this.tokenCache.delete(token);
        }
      }
    }, 5 * 60 * 1000);
  }

  private isTokenExpired(cached: CachedToken): boolean {
    return cached.expiresAt <= Date.now();
  }
}
```

## Advanced Rate Limiting and Throttling

Effective rate limiting and throttling mechanisms are essential for protecting APIs from abuse, ensuring fair resource allocation, and maintaining service availability under high load conditions. Advanced rate limiting goes beyond simple request counting to implement sophisticated algorithms that can adapt to different usage patterns and provide granular control over resource consumption.

Modern rate limiting systems must support multiple dimensions of limiting, including per-user, per-API, per-service, and global limits. They must also implement intelligent algorithms that can handle burst traffic while preventing sustained abuse and provide meaningful feedback to clients about their current usage status.

```typescript
// Advanced rate limiting and throttling system
interface RateLimitConfig {
  algorithm: RateLimitAlgorithm;
  limits: RateLimit[];
  keyGenerators: KeyGenerator[];
  burstHandling: BurstConfig;
  quotaManagement: QuotaConfig;
  distributedMode: boolean;
}

interface RateLimit {
  name: string;
  maxRequests: number;
  windowSize: number; // seconds
  windowType: WindowType;
  scope: LimitScope;
  overrideRules: OverrideRule[];
}

interface QuotaConfig {
  enabled: boolean;
  resetPeriod: ResetPeriod;
  quotaTypes: QuotaType[];
  gracePeriod: number;
  warningThresholds: number[];
}

enum RateLimitAlgorithm {
  TOKEN_BUCKET = 'TOKEN_BUCKET',
  LEAKY_BUCKET = 'LEAKY_BUCKET',
  FIXED_WINDOW = 'FIXED_WINDOW',
  SLIDING_WINDOW = 'SLIDING_WINDOW',
  ADAPTIVE = 'ADAPTIVE'
}

enum WindowType {
  FIXED = 'FIXED',
  SLIDING = 'SLIDING',
  ROLLING = 'ROLLING'
}

enum LimitScope {
  USER = 'USER',
  API_KEY = 'API_KEY',
  IP_ADDRESS = 'IP_ADDRESS',
  SERVICE = 'SERVICE',
  GLOBAL = 'GLOBAL'
}

export class AdvancedRateLimiter {
  private config: RateLimitConfig;
  private algorithms: Map<RateLimitAlgorithm, RateLimitingAlgorithm> = new Map();
  private quotaStore: QuotaStore;
  private metricsCollector: MetricsCollector;
  private redisClient: any;

  constructor(config: RateLimitConfig, redisClient: any) {
    this.config = config;
    this.redisClient = redisClient;
    this.quotaStore = new QuotaStore(redisClient);
    this.metricsCollector = new MetricsCollector();
    
    this.initializeAlgorithms();
    this.startBackgroundTasks();
  }

  async checkRateLimit(request: RateLimitRequest): Promise<RateLimitResult> {
    const results: RateLimitResult[] = [];
    
    // Generate all applicable rate limit keys
    const keys = await this.generateRateLimitKeys(request);
    
    // Check each applicable rate limit
    for (const key of keys) {
      const limit = this.findApplicableLimit(key, request);
      if (!limit) continue;
      
      const algorithm = this.algorithms.get(this.config.algorithm);
      if (!algorithm) {
        throw new Error(`Unsupported rate limiting algorithm: ${this.config.algorithm}`);
      }
      
      const result = await algorithm.checkLimit(key, limit, request);
      results.push(result);
      
      // If any limit is exceeded, return immediately
      if (!result.allowed) {
        await this.recordViolation(key, limit, request, result);
        return result;
      }
    }
    
    // All limits passed, consume tokens/quotas
    for (const key of keys) {
      const limit = this.findApplicableLimit(key, request);
      if (limit) {
        const algorithm = this.algorithms.get(this.config.algorithm);
        await algorithm?.consumeToken(key, limit, request);
      }
    }
    
    // Check quota limits if enabled
    if (this.config.quotaManagement.enabled) {
      const quotaResult = await this.checkQuotaLimits(request);
      if (!quotaResult.allowed) {
        return quotaResult;
      }
    }
    
    // Return the most restrictive successful result
    const mostRestrictive = results.reduce((prev, current) => 
      current.remainingRequests < prev.remainingRequests ? current : prev
    );
    
    await this.recordSuccessfulRequest(request, mostRestrictive);
    
    return mostRestrictive;
  }

  private async generateRateLimitKeys(request: RateLimitRequest): Promise<RateLimitKey[]> {
    const keys: RateLimitKey[] = [];
    
    for (const generator of this.config.keyGenerators) {
      const key = await generator.generateKey(request);
      keys.push(key);
    }
    
    return keys;
  }

  private initializeAlgorithms(): void {
    this.algorithms.set(RateLimitAlgorithm.TOKEN_BUCKET, new TokenBucketAlgorithm(this.redisClient));
    this.algorithms.set(RateLimitAlgorithm.LEAKY_BUCKET, new LeakyBucketAlgorithm(this.redisClient));
    this.algorithms.set(RateLimitAlgorithm.FIXED_WINDOW, new FixedWindowAlgorithm(this.redisClient));
    this.algorithms.set(RateLimitAlgorithm.SLIDING_WINDOW, new SlidingWindowAlgorithm(this.redisClient));
    this.algorithms.set(RateLimitAlgorithm.ADAPTIVE, new AdaptiveAlgorithm(this.redisClient, this.metricsCollector));
  }
}

class TokenBucketAlgorithm implements RateLimitingAlgorithm {
  constructor(private redisClient: any) {}

  async checkLimit(key: RateLimitKey, limit: RateLimit, request: RateLimitRequest): Promise<RateLimitResult> {
    const bucketKey = `token_bucket:${key.value}`;
    const now = Date.now();
    
    // Get current bucket state
    const bucketData = await this.getBucketState(bucketKey);
    
    // Calculate tokens to add based on time elapsed
    const tokensToAdd = this.calculateTokensToAdd(bucketData.lastRefill, now, limit);
    const currentTokens = Math.min(bucketData.tokens + tokensToAdd, limit.maxRequests);
    
    if (currentTokens >= 1) {
      // Allow request and update bucket
      const newTokens = currentTokens - 1;
      await this.updateBucketState(bucketKey, newTokens, now);
      
      return {
        allowed: true,
        remainingRequests: Math.floor(newTokens),
        resetTime: new Date(now + (limit.maxRequests - newTokens) * (limit.windowSize * 1000 / limit.maxRequests)),
        retryAfter: 0
      };
    } else {
      // Request denied
      const refillRate = limit.maxRequests / limit.windowSize; // tokens per second
      const timeToNextToken = (1 - currentTokens) / refillRate;
      
      return {
        allowed: false,
        remainingRequests: 0,
        resetTime: new Date(now + timeToNextToken * 1000),
        retryAfter: Math.ceil(timeToNextToken)
      };
    }
  }

  async consumeToken(key: RateLimitKey, limit: RateLimit, request: RateLimitRequest): Promise<void> {
    // Token consumption is handled in checkLimit for token bucket
  }

  private async getBucketState(bucketKey: string): Promise<BucketState> {
    const data = await this.redisClient.hmget(bucketKey, 'tokens', 'lastRefill');
    
    return {
      tokens: parseFloat(data[0]) || 0,
      lastRefill: parseInt(data[1]) || Date.now()
    };
  }

  private async updateBucketState(bucketKey: string, tokens: number, timestamp: number): Promise<void> {
    await this.redisClient.hmset(bucketKey, 'tokens', tokens.toString(), 'lastRefill', timestamp.toString());
    await this.redisClient.expire(bucketKey, 3600); // 1 hour TTL
  }

  private calculateTokensToAdd(lastRefill: number, now: number, limit: RateLimit): number {
    const timeElapsed = (now - lastRefill) / 1000; // seconds
    const refillRate = limit.maxRequests / limit.windowSize; // tokens per second
    return timeElapsed * refillRate;
  }
}

class SlidingWindowAlgorithm implements RateLimitingAlgorithm {
  constructor(private redisClient: any) {}

  async checkLimit(key: RateLimitKey, limit: RateLimit, request: RateLimitRequest): Promise<RateLimitResult> {
    const windowKey = `sliding_window:${key.value}`;
    const now = Date.now();
    const windowStart = now - (limit.windowSize * 1000);
    
    // Remove expired entries and count current requests
    await this.redisClient.zremrangebyscore(windowKey, '-inf', windowStart);
    const currentCount = await this.redisClient.zcard(windowKey);
    
    if (currentCount < limit.maxRequests) {
      // Allow request
      return {
        allowed: true,
        remainingRequests: limit.maxRequests - currentCount - 1,
        resetTime: new Date(now + limit.windowSize * 1000),
        retryAfter: 0
      };
    } else {
      // Request denied - find when oldest request will expire
      const oldestRequest = await this.redisClient.zrange(windowKey, 0, 0, 'WITHSCORES');
      const retryAfter = oldestRequest.length > 0 
        ? Math.ceil((parseInt(oldestRequest[1]) + limit.windowSize * 1000 - now) / 1000)
        : limit.windowSize;
      
      return {
        allowed: false,
        remainingRequests: 0,
        resetTime: new Date(now + retryAfter * 1000),
        retryAfter
      };
    }
  }

  async consumeToken(key: RateLimitKey, limit: RateLimit, request: RateLimitRequest): Promise<void> {
    const windowKey = `sliding_window:${key.value}`;
    const now = Date.now();
    const requestId = `${now}_${Math.random()}`;
    
    // Add current request to window
    await this.redisClient.zadd(windowKey, now, requestId);
    await this.redisClient.expire(windowKey, limit.windowSize + 60); // Add buffer to TTL
  }
}

class AdaptiveAlgorithm implements RateLimitingAlgorithm {
  constructor(
    private redisClient: any, 
    private metricsCollector: MetricsCollector
  ) {}

  async checkLimit(key: RateLimitKey, limit: RateLimit, request: RateLimitRequest): Promise<RateLimitResult> {
    // Get current system metrics
    const metrics = await this.metricsCollector.getCurrentMetrics();
    
    // Adjust limit based on system load
    const adjustedLimit = this.calculateAdaptiveLimit(limit, metrics, key);
    
    // Use sliding window algorithm with adjusted limit
    const slidingWindow = new SlidingWindowAlgorithm(this.redisClient);
    const result = await slidingWindow.checkLimit(key, adjustedLimit, request);
    
    // Track adaptation for future adjustments
    await this.trackAdaptation(key, limit, adjustedLimit, metrics, result);
    
    return result;
  }

  async consumeToken(key: RateLimitKey, limit: RateLimit, request: RateLimitRequest): Promise<void> {
    const metrics = await this.metricsCollector.getCurrentMetrics();
    const adjustedLimit = this.calculateAdaptiveLimit(limit, metrics, key);
    
    const slidingWindow = new SlidingWindowAlgorithm(this.redisClient);
    await slidingWindow.consumeToken(key, adjustedLimit, request);
  }

  private calculateAdaptiveLimit(
    baseLimit: RateLimit,
    metrics: SystemMetrics,
    key: RateLimitKey
  ): RateLimit {
    let adjustmentFactor = 1.0;
    
    // Adjust based on CPU usage
    if (metrics.cpuUsage > 80) {
      adjustmentFactor *= 0.5; // Reduce limit by 50%
    } else if (metrics.cpuUsage < 30) {
      adjustmentFactor *= 1.2; // Increase limit by 20%
    }
    
    // Adjust based on memory usage
    if (metrics.memoryUsage > 85) {
      adjustmentFactor *= 0.7; // Reduce limit by 30%
    }
    
    // Adjust based on error rate
    if (metrics.errorRate > 5) {
      adjustmentFactor *= 0.6; // Reduce limit by 40%
    }
    
    // Adjust based on response time
    if (metrics.avgResponseTime > 2000) { // 2 seconds
      adjustmentFactor *= 0.8; // Reduce limit by 20%
    }
    
    // Apply user/service specific adjustments
    const userAdjustment = this.getUserSpecificAdjustment(key);
    adjustmentFactor *= userAdjustment;
    
    return {
      ...baseLimit,
      maxRequests: Math.max(1, Math.floor(baseLimit.maxRequests * adjustmentFactor))
    };
  }

  private getUserSpecificAdjustment(key: RateLimitKey): number {
    // Implement user-specific adjustments based on:
    // - Historical behavior
    // - Service tier
    // - Trust score
    // - Geographic location
    return 1.0; // Simplified for example
  }

  private async trackAdaptation(
    key: RateLimitKey,
    originalLimit: RateLimit,
    adjustedLimit: RateLimit,
    metrics: SystemMetrics,
    result: RateLimitResult
  ): Promise<void> {
    const adaptationData = {
      timestamp: Date.now(),
      key: key.value,
      originalLimit: originalLimit.maxRequests,
      adjustedLimit: adjustedLimit.maxRequests,
      adjustmentFactor: adjustedLimit.maxRequests / originalLimit.maxRequests,
      systemMetrics: metrics,
      requestAllowed: result.allowed
    };
    
    await this.metricsCollector.recordAdaptation(adaptationData);
  }
}

export class QuotaManager {
  constructor(private quotaStore: QuotaStore, private config: QuotaConfig) {}

  async checkQuota(request: RateLimitRequest): Promise<QuotaCheckResult> {
    const quotaKeys = await this.generateQuotaKeys(request);
    
    for (const quotaKey of quotaKeys) {
      const usage = await this.quotaStore.getUsage(quotaKey);
      const quota = await this.getQuotaForKey(quotaKey);
      
      if (usage >= quota.limit) {
        return {
          allowed: false,
          quotaType: quota.type,
          used: usage,
          limit: quota.limit,
          resetTime: quota.resetTime,
          retryAfter: this.calculateRetryAfter(quota.resetTime)
        };
      }
      
      // Check warning thresholds
      const usagePercentage = (usage / quota.limit) * 100;
      if (this.config.warningThresholds.some(threshold => usagePercentage >= threshold)) {
        await this.sendQuotaWarning(quotaKey, usage, quota);
      }
    }
    
    return {
      allowed: true
    };
  }

  async consumeQuota(request: RateLimitRequest, amount: number = 1): Promise<void> {
    const quotaKeys = await this.generateQuotaKeys(request);
    
    for (const quotaKey of quotaKeys) {
      await this.quotaStore.incrementUsage(quotaKey, amount);
    }
  }

  async resetQuota(quotaKey: string): Promise<void> {
    await this.quotaStore.resetUsage(quotaKey);
  }

  private calculateRetryAfter(resetTime: Date): number {
    return Math.max(0, Math.ceil((resetTime.getTime() - Date.now()) / 1000));
  }
}
```

## Conclusion

API security in cloud-native applications requires a comprehensive, multi-layered approach that addresses authentication, authorization, input validation, rate limiting, and threat detection. The implementation of these security measures must balance protection with performance, ensuring that legitimate users can access services efficiently while preventing unauthorized access and malicious activities.

The patterns and implementations explored in this post demonstrate how modern API security systems can provide robust protection through centralized gateways, standardized authentication protocols, and intelligent rate limiting mechanisms. These systems must be designed to handle the scale and complexity of cloud-native environments while providing the flexibility needed to adapt to changing security requirements and threat landscapes.

As cloud-native applications continue to evolve, API security systems must incorporate emerging technologies such as machine learning for threat detection, zero-trust architectures for enhanced verification, and adaptive security controls that can respond dynamically to changing conditions. Organizations implementing these patterns should focus on creating security systems that are both comprehensive and maintainable, providing the protection needed for modern applications while supporting the agility and scalability that cloud-native architectures enable. The security foundation established by these API protection strategies will prove essential as we explore container and serverless security considerations in the next post of this series.
