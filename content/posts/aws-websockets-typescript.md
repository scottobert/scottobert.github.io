---
title: "Real-time Applications with AWS WebSockets and TypeScript"
date: 2023-08-13T10:00:00-07:00
draft: false
categories: ["Cloud Computing", "Real-time Applications"]
tags:
- AWS
- TypeScript
- WebSockets
- Real-time
- API Gateway
- Serverless
series: "AWS and Typescript"
---

Modern applications increasingly demand real-time capabilities—from live chat systems and collaborative editing to real-time dashboards and gaming. In this final post of our AWS and TypeScript series, we'll explore how to build scalable real-time applications using AWS API Gateway WebSocket APIs, Lambda functions, and TypeScript to create robust, type-safe real-time communication systems.

{{< plantuml id="websocket-architecture" >}}
@startuml WebSocket Architecture
!define RECTANGLE class

cloud "Client Applications" as clients
package "AWS Cloud" {
  rectangle "API Gateway WebSocket" as apigw {
    rectangle "Connect Route" as connect
    rectangle "Disconnect Route" as disconnect
    rectangle "Message Routes" as routes
  }
  
  package "Lambda Functions" {
    rectangle "Connection Handler" as conn_handler
    rectangle "Message Handler" as msg_handler
    rectangle "Room Manager" as room_handler
    rectangle "Broadcast Service" as broadcast
  }
  
  database "DynamoDB" as dynamo {
    rectangle "Connections Table" as conn_table
    rectangle "Messages Table" as msg_table
    rectangle "Rooms Table" as room_table
  }
  
  rectangle "API Gateway Management API" as mgmt_api
}

clients <--> connect : WebSocket Connection
clients <--> disconnect : WebSocket Disconnection
clients <--> routes : Real-time Messages

connect --> conn_handler : $connect
disconnect --> conn_handler : $disconnect
routes --> msg_handler : Custom Routes
routes --> room_handler : Room Operations

conn_handler --> conn_table : Store Connection
msg_handler --> msg_table : Store Message
room_handler --> room_table : Manage Rooms

broadcast --> mgmt_api : Send to Connections
mgmt_api --> clients : Real-time Updates

note right of apigw
  • Persistent connections
  • Bidirectional communication  • Auto-scaling
  • Route-based message handling
end note

note right of dynamo
  • Connection state storage
  • Message persistence
  • Room membership
  • TTL for cleanup
end note
@enduml
{{< /plantuml >}}

## Understanding WebSocket APIs with AWS

AWS API Gateway WebSocket APIs provide a fully managed service for building real-time, bidirectional communication applications. Key advantages include:

- **Persistent Connections**: Maintain long-lived connections for instant messaging
- **Automatic Scaling**: Handle thousands of concurrent connections without infrastructure management
- **Pay-per-Use**: Cost-effective pricing model with no idle charges
- **AWS Integration**: Seamless integration with Lambda, DynamoDB, and other AWS services
- **Route-Based Architecture**: Organize message handling with custom routes

## Prerequisites

Essential knowledge and tools for WebSocket development:

- **Previous Series Posts**: Lambda, DynamoDB, and API Gateway fundamentals
- **AWS SDK v3**: API Gateway Management API and DynamoDB clients
- **WebSocket Concepts**: Connection lifecycle, message routing, and error handling
- **Real-time Patterns**: Broadcasting, presence management, and state synchronization

## Type-Safe WebSocket Architecture

Define comprehensive type definitions for WebSocket operations:

```typescript
// src/types/websocket.ts
export interface WebSocketEvent {
  requestContext: {
    connectionId: string;
    routeKey: string;
    stage: string;
    apiId: string;
    domainName: string;
    eventType: 'CONNECT' | 'DISCONNECT' | 'MESSAGE';
    messageId?: string;
    requestTime: string;
    requestTimeEpoch: number;
    identity: {
      sourceIp: string;
      userAgent: string;
    };
    authorizer?: {
      userId: string;
      username: string;
      [key: string]: any;
    };
  };
  body?: string;
  isBase64Encoded: boolean;
  headers: Record<string, string>;
  queryStringParameters?: Record<string, string>;
}

export interface WebSocketResponse {
  statusCode: number;
  headers?: Record<string, string>;
  body?: string;
}

export interface ConnectionData {
  connectionId: string;
  userId: string;
  username: string;
  roomId?: string;
  connectedAt: string;
  lastSeenAt: string;
  userAgent: string;
  ipAddress: string;
}

export interface ChatMessage {
  messageId: string;
  roomId: string;
  userId: string;
  username: string;
  content: string;
  messageType: MessageType;
  timestamp: string;
  editedAt?: string;
  replyToMessageId?: string;
}

export interface ChatRoom {
  roomId: string;
  name: string;
  description?: string;
  createdBy: string;
  createdAt: string;
  isPrivate: boolean;
  members: string[];
  lastMessageAt?: string;
  lastMessagePreview?: string;
}

export enum MessageType {
  TEXT = 'TEXT',
  IMAGE = 'IMAGE',
  FILE = 'FILE',
  SYSTEM = 'SYSTEM',
  TYPING = 'TYPING'
}

export enum WebSocketAction {
  JOIN_ROOM = 'joinRoom',
  LEAVE_ROOM = 'leaveRoom',
  SEND_MESSAGE = 'sendMessage',
  EDIT_MESSAGE = 'editMessage',
  DELETE_MESSAGE = 'deleteMessage',
  TYPING_START = 'typingStart',
  TYPING_STOP = 'typingStop',
  LIST_ROOMS = 'listRooms',
  CREATE_ROOM = 'createRoom',
  GET_ROOM_HISTORY = 'getRoomHistory'
}

export interface WebSocketMessage {
  action: WebSocketAction;
  data: any;
  requestId?: string;
}

export interface WebSocketBroadcast {
  type: 'message' | 'user_joined' | 'user_left' | 'typing' | 'room_update';
  data: any;
  roomId?: string;
  excludeConnectionId?: string;
}
```

## Connection Management Service

{{< plantuml id="connection-lifecycle" >}}
@startuml Connection Lifecycle
!define RECTANGLE class

participant "Client" as client
participant "API Gateway" as apigw
participant "Connect Handler" as connect
participant "Message Handler" as message
participant "Disconnect Handler" as disconnect
participant "DynamoDB" as dynamo
participant "Broadcast Service" as broadcast

client -> apigw : WebSocket Connect
apigw -> connect : $connect route
connect -> dynamo : Store connection data
connect -> broadcast : Notify room of new user
connect --> client : Connection established

loop Active Session
  client -> apigw : Send message
  apigw -> message : Route message
  message -> dynamo : Store message
  message -> broadcast : Send to room members
  broadcast --> client : Real-time delivery
end

client -> apigw : WebSocket Disconnect
apigw -> disconnect : $disconnect route
disconnect -> dynamo : Remove connection
disconnect -> broadcast : Notify room of user leaving
@enduml
{{< /plantuml >}}

Implement robust connection management with DynamoDB storage:

```typescript
// src/services/connection-service.ts
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { 
  DynamoDBDocumentClient, 
  PutCommand, 
  GetCommand, 
  DeleteCommand, 
  QueryCommand,
  UpdateCommand
} from '@aws-sdk/lib-dynamodb';
import { ConnectionData } from '../types/websocket';

export class ConnectionService {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;

  constructor(tableName: string) {
    this.docClient = DynamoDBDocumentClient.from(new DynamoDBClient({}));
    this.tableName = tableName;
  }

  async saveConnection(connectionData: ConnectionData): Promise<void> {
    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        pk: `CONNECTION#${connectionData.connectionId}`,
        sk: `CONNECTION#${connectionData.connectionId}`,
        gsi1pk: `USER#${connectionData.userId}`,
        gsi1sk: `CONNECTION#${connectionData.connectedAt}`,
        gsi2pk: connectionData.roomId ? `ROOM#${connectionData.roomId}` : undefined,
        gsi2sk: connectionData.roomId ? `CONNECTION#${connectionData.connectionId}` : undefined,
        entityType: 'CONNECTION',
        ...connectionData,
        ttl: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours TTL
      }
    }));
  }

  async getConnection(connectionId: string): Promise<ConnectionData | null> {
    const { Item } = await this.docClient.send(new GetCommand({
      TableName: this.tableName,
      Key: { pk: `CONNECTION#${connectionId}`, sk: `CONNECTION#${connectionId}` }
    }));

    return Item ? this.mapItemToConnection(Item) : null;
  }

  async deleteConnection(connectionId: string): Promise<void> {
    await this.docClient.send(new DeleteCommand({
      TableName: this.tableName,
      Key: { pk: `CONNECTION#${connectionId}`, sk: `CONNECTION#${connectionId}` }
    }));
  }

  async updateConnectionRoom(connectionId: string, roomId: string | null): Promise<void> {
    const updateExpression = roomId 
      ? 'SET roomId = :roomId, gsi2pk = :gsi2pk, gsi2sk = :gsi2sk, lastSeenAt = :lastSeenAt'
      : 'SET lastSeenAt = :lastSeenAt REMOVE roomId, gsi2pk, gsi2sk';

    const attributeValues: Record<string, any> = {
      ':lastSeenAt': new Date().toISOString()
    };

    if (roomId) {
      Object.assign(attributeValues, {
        ':roomId': roomId,
        ':gsi2pk': `ROOM#${roomId}`,
        ':gsi2sk': `CONNECTION#${connectionId}`
      });
    }

    await this.docClient.send(new UpdateCommand({
      TableName: this.tableName,
      Key: { pk: `CONNECTION#${connectionId}`, sk: `CONNECTION#${connectionId}` },
      UpdateExpression: updateExpression,
      ExpressionAttributeValues: attributeValues
    }));
  }

  async getConnectionsByRoom(roomId: string): Promise<ConnectionData[]> {
    const { Items } = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: 'GSI2',
      KeyConditionExpression: 'gsi2pk = :roomPk',
      ExpressionAttributeValues: { ':roomPk': `ROOM#${roomId}` }
    }));

    return Items?.map(this.mapItemToConnection) || [];
  }

  async getConnectionsByUser(userId: string): Promise<ConnectionData[]> {
    const { Items } = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: 'GSI1',
      KeyConditionExpression: 'gsi1pk = :userPk',
      ExpressionAttributeValues: { ':userPk': `USER#${userId}` }
    }));

    return Items?.map(this.mapItemToConnection) || [];
  }

  private mapItemToConnection(item: any): ConnectionData {
    return {
      connectionId: item.connectionId,
      userId: item.userId,
      username: item.username,
      roomId: item.roomId,
      connectedAt: item.connectedAt,
      lastSeenAt: item.lastSeenAt,
      userAgent: item.userAgent,
      ipAddress: item.ipAddress
    };
  }
}
```

## WebSocket Communication Service

Create a service for sending messages to WebSocket connections:

```typescript
// src/services/websocket-service.ts
import { ApiGatewayManagementApiClient, PostToConnectionCommand } from '@aws-sdk/client-apigatewaymanagementapi';
import { ConnectionService } from './connection-service';
import { WebSocketBroadcast } from '../types/websocket';

export class WebSocketService {
  private apiGatewayClient: ApiGatewayManagementApiClient;
  private connectionService: ConnectionService;

  constructor(endpoint: string, connectionService: ConnectionService) {
    this.apiGatewayClient = new ApiGatewayManagementApiClient({ endpoint });
    this.connectionService = connectionService;
  }

  async sendToConnection(connectionId: string, data: any): Promise<boolean> {
    try {
      await this.apiGatewayClient.send(new PostToConnectionCommand({
        ConnectionId: connectionId,
        Data: JSON.stringify(data)
      }));
      return true;
    } catch (error) {
      console.error(`Failed to send to ${connectionId}:`, error);
      
      // Clean up stale connections (410 Gone)
      if (error.statusCode === 410) {
        await this.connectionService.deleteConnection(connectionId);
      }
      
      return false;
    }
  }

  async broadcastToRoom(broadcast: WebSocketBroadcast): Promise<{ successful: number; failed: number }> {
    if (!broadcast.roomId) {
      throw new Error('Room ID required for room broadcasts');
    }

    const connections = await this.connectionService.getConnectionsByRoom(broadcast.roomId);
    const filteredConnections = connections.filter(
      conn => conn.connectionId !== broadcast.excludeConnectionId
    );

    const results = await Promise.allSettled(
      filteredConnections.map(connection =>
        this.sendToConnection(connection.connectionId, broadcast.data)
      )
    );

    const successful = results.filter(
      result => result.status === 'fulfilled' && result.value
    ).length;

    return {
      successful,
      failed: filteredConnections.length - successful
    };
  }

  async broadcastToUser(
    userId: string, 
    data: any, 
    excludeConnectionId?: string
  ): Promise<{ successful: number; failed: number }> {
    const connections = await this.connectionService.getConnectionsByUser(userId);
    const filteredConnections = connections.filter(
      conn => conn.connectionId !== excludeConnectionId
    );

    const results = await Promise.allSettled(
      filteredConnections.map(connection =>
        this.sendToConnection(connection.connectionId, data)
      )
    );

    const successful = results.filter(
      result => result.status === 'fulfilled' && result.value
    ).length;

    return {
      successful,
      failed: filteredConnections.length - successful
    };
  }

  async sendError(connectionId: string, error: string, requestId?: string): Promise<void> {
    await this.sendToConnection(connectionId, {
      type: 'error',
      error,
      requestId,
      timestamp: new Date().toISOString()
    });
  }

  async sendSuccess(connectionId: string, data: any, requestId?: string): Promise<void> {
    await this.sendToConnection(connectionId, {
      type: 'success',
      data,
      requestId,
      timestamp: new Date().toISOString()
    });
  }
}
```

## Chat and Room Management

{{< plantuml id="message-flow" >}}
@startuml Message Flow
!define RECTANGLE class

participant "User A" as userA
participant "User B" as userB
participant "WebSocket API" as api
participant "Message Handler" as handler
participant "Chat Service" as chat
participant "DynamoDB" as dynamo
participant "Broadcast Service" as broadcast

userA -> api : Send message to room
api -> handler : Route to message handler
handler -> chat : Store message
chat -> dynamo : Persist message data

handler -> broadcast : Broadcast to room
broadcast -> dynamo : Get room connections
dynamo -> broadcast : Return active connections
broadcast -> api : Send to all connections
api -> userB : Real-time message delivery
api -> userA : Delivery confirmation

note right of chat
  • Message validation
  • Content filtering
  • Thread management
  • Edit/delete support
end note

note right of broadcast
  • Connection filtering
  • Stale connection cleanup
  • Delivery status tracking
  • Error handling
end note
@enduml
{{< /plantuml >}}

Implement comprehensive chat functionality:

```typescript
// src/services/chat-service.ts
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { 
  DynamoDBDocumentClient, 
  PutCommand, 
  GetCommand, 
  QueryCommand,
  UpdateCommand
} from '@aws-sdk/lib-dynamodb';
import { v4 as uuidv4 } from 'uuid';
import { ChatMessage, ChatRoom, MessageType } from '../types/websocket';

export class ChatService {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;

  constructor(tableName: string) {
    this.docClient = DynamoDBDocumentClient.from(new DynamoDBClient({}));
    this.tableName = tableName;
  }

  async createRoom(roomData: {
    name: string;
    description?: string;
    createdBy: string;
    isPrivate: boolean;
    members: string[];
  }): Promise<ChatRoom> {
    const roomId = uuidv4();
    const timestamp = new Date().toISOString();

    const room: ChatRoom = {
      roomId,
      name: roomData.name,
      description: roomData.description,
      createdBy: roomData.createdBy,
      createdAt: timestamp,
      isPrivate: roomData.isPrivate,
      members: [...new Set([roomData.createdBy, ...roomData.members])]
    };

    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        pk: `ROOM#${roomId}`,
        sk: `ROOM#${roomId}`,
        gsi1pk: `ROOMS#${roomData.isPrivate ? 'PRIVATE' : 'PUBLIC'}`,
        gsi1sk: `ROOM#${timestamp}`,
        entityType: 'ROOM',
        ...room
      }
    }));

    return room;
  }

  async getRoom(roomId: string): Promise<ChatRoom | null> {
    const { Item } = await this.docClient.send(new GetCommand({
      TableName: this.tableName,
      Key: { pk: `ROOM#${roomId}`, sk: `ROOM#${roomId}` }
    }));

    return Item ? this.mapItemToRoom(Item) : null;
  }

  async listRooms(isPrivate: boolean = false, limit: number = 50): Promise<ChatRoom[]> {
    const { Items } = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: 'GSI1',
      KeyConditionExpression: 'gsi1pk = :roomType',
      ExpressionAttributeValues: {
        ':roomType': `ROOMS#${isPrivate ? 'PRIVATE' : 'PUBLIC'}`
      },
      Limit: limit,
      ScanIndexForward: false
    }));

    return Items?.map(this.mapItemToRoom) || [];
  }

  async sendMessage(messageData: {
    roomId: string;
    userId: string;
    username: string;
    content: string;
    messageType?: MessageType;
    replyToMessageId?: string;
  }): Promise<ChatMessage> {
    const messageId = uuidv4();
    const timestamp = new Date().toISOString();

    const message: ChatMessage = {
      messageId,
      roomId: messageData.roomId,
      userId: messageData.userId,
      username: messageData.username,
      content: messageData.content,
      messageType: messageData.messageType || MessageType.TEXT,
      timestamp,
      replyToMessageId: messageData.replyToMessageId
    };

    // Store message
    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        pk: `ROOM#${messageData.roomId}`,
        sk: `MESSAGE#${timestamp}#${messageId}`,
        gsi1pk: `MESSAGE#${messageId}`,
        gsi1sk: `MESSAGE#${messageId}`,
        entityType: 'MESSAGE',
        ...message
      }
    }));

    // Update room's last message
    await this.updateRoomLastMessage(messageData.roomId, message);

    return message;
  }

  async getRoomMessages(
    roomId: string,
    limit: number = 50,
    exclusiveStartKey?: Record<string, any>
  ): Promise<{ messages: ChatMessage[]; lastEvaluatedKey?: Record<string, any> }> {
    const { Items, LastEvaluatedKey } = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: 'pk = :roomPk AND begins_with(sk, :messagePrefix)',
      ExpressionAttributeValues: {
        ':roomPk': `ROOM#${roomId}`,
        ':messagePrefix': 'MESSAGE#'
      },
      Limit: limit,
      ScanIndexForward: false, // Latest messages first
      ExclusiveStartKey: exclusiveStartKey
    }));

    return {
      messages: Items?.map(this.mapItemToMessage) || [],
      lastEvaluatedKey: LastEvaluatedKey
    };
  }

  async editMessage(
    messageId: string,
    newContent: string,
    userId: string
  ): Promise<ChatMessage | null> {
    const timestamp = new Date().toISOString();

    try {
      const { Attributes } = await this.docClient.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk: `MESSAGE#${messageId}`, sk: `MESSAGE#${messageId}` },
        UpdateExpression: 'SET content = :content, editedAt = :editedAt',
        ConditionExpression: 'userId = :userId',
        ExpressionAttributeValues: {
          ':content': newContent,
          ':editedAt': timestamp,
          ':userId': userId
        },
        ReturnValues: 'ALL_NEW'
      }));

      return Attributes ? this.mapItemToMessage(Attributes) : null;
    } catch (error) {
      if (error.name === 'ConditionalCheckFailedException') {
        throw new Error('Unauthorized to edit this message');
      }
      throw error;
    }
  }

  private async updateRoomLastMessage(roomId: string, message: ChatMessage): Promise<void> {
    const preview = message.content.length > 100 
      ? `${message.content.substring(0, 100)}...` 
      : message.content;

    await this.docClient.send(new UpdateCommand({
      TableName: this.tableName,
      Key: { pk: `ROOM#${roomId}`, sk: `ROOM#${roomId}` },
      UpdateExpression: 'SET lastMessageAt = :timestamp, lastMessagePreview = :preview',
      ExpressionAttributeValues: {
        ':timestamp': message.timestamp,
        ':preview': `${message.username}: ${preview}`
      }
    }));
  }

  private mapItemToRoom(item: any): ChatRoom {
    return {
      roomId: item.roomId,
      name: item.name,
      description: item.description,
      createdBy: item.createdBy,
      createdAt: item.createdAt,
      isPrivate: item.isPrivate,
      members: item.members,
      lastMessageAt: item.lastMessageAt,
      lastMessagePreview: item.lastMessagePreview
    };
  }

  private mapItemToMessage(item: any): ChatMessage {
    return {
      messageId: item.messageId,
      roomId: item.roomId,
      userId: item.userId,
      username: item.username,
      content: item.content,
      messageType: item.messageType,
      timestamp: item.timestamp,
      editedAt: item.editedAt,
      replyToMessageId: item.replyToMessageId    };
  }
}
```

## WebSocket Lambda Handlers

Implement the Lambda functions that handle WebSocket events:

```typescript
// src/handlers/websocket/connect.ts
import { WebSocketEvent, WebSocketResponse } from '../../types/websocket';
import { ConnectionService } from '../../services/connection-service';

const connectionService = new ConnectionService(process.env.TABLE_NAME!);

export const handler = async (event: WebSocketEvent): Promise<WebSocketResponse> => {
  console.log('WebSocket connection event:', JSON.stringify(event, null, 2));

  try {
    const { connectionId, authorizer, identity, requestTime } = event.requestContext;

    if (!authorizer || !authorizer.userId || !authorizer.username) {
      console.error('Missing authorization data');
      return { statusCode: 401 };
    }

    const connectionData = {
      connectionId,
      userId: authorizer.userId,
      username: authorizer.username,
      connectedAt: requestTime,
      lastSeenAt: requestTime,
      userAgent: identity.userAgent,
      ipAddress: identity.sourceIp,
    };

    await connectionService.saveConnection(connectionData);

    console.log(`Connection ${connectionId} saved for user ${authorizer.userId}`);
    return { statusCode: 200 };
  } catch (error) {
    console.error('Error handling connection:', error);
    return { statusCode: 500 };
  }
};
```

```typescript
// src/handlers/websocket/disconnect.ts
import { WebSocketEvent, WebSocketResponse } from '../../types/websocket';
import { ConnectionService } from '../../services/connection-service';
import { WebSocketService } from '../../services/websocket-service';

const connectionService = new ConnectionService(process.env.TABLE_NAME!);
const websocketService = new WebSocketService(
  `https://${process.env.API_ID}.execute-api.${process.env.REGION}.amazonaws.com/${process.env.STAGE}`,
  connectionService
);

export const handler = async (event: WebSocketEvent): Promise<WebSocketResponse> => {
  console.log('WebSocket disconnect event:', JSON.stringify(event, null, 2));

  try {
    const { connectionId } = event.requestContext;

    // Get connection data before deleting
    const connection = await connectionService.getConnection(connectionId);
    
    if (connection && connection.roomId) {
      // Notify room members that user left
      await websocketService.broadcastToRoom({
        type: 'user_left',
        data: {
          userId: connection.userId,
          username: connection.username,
          leftAt: new Date().toISOString(),
        },
        roomId: connection.roomId,
        excludeConnectionId: connectionId,
      });
    }

    // Remove connection from database
    await connectionService.deleteConnection(connectionId);

    console.log(`Connection ${connectionId} removed`);
    return { statusCode: 200 };
  } catch (error) {
    console.error('Error handling disconnection:', error);
    return { statusCode: 500 };
  }
};
```

```typescript
// src/handlers/websocket/message.ts
import { WebSocketEvent, WebSocketResponse, WebSocketMessage, WebSocketAction } from '../../types/websocket';
import { ConnectionService } from '../../services/connection-service';
import { ChatService } from '../../services/chat-service';
import { WebSocketService } from '../../services/websocket-service';
import { MessageType } from '../../types/websocket';

const connectionService = new ConnectionService(process.env.TABLE_NAME!);
const chatService = new ChatService(process.env.TABLE_NAME!);
const websocketService = new WebSocketService(
  `https://${process.env.API_ID}.execute-api.${process.env.REGION}.amazonaws.com/${process.env.STAGE}`,
  connectionService
);

export const handler = async (event: WebSocketEvent): Promise<WebSocketResponse> => {
  console.log('WebSocket message event:', JSON.stringify(event, null, 2));

  try {
    const { connectionId } = event.requestContext;
    
    if (!event.body) {
      await websocketService.sendError(connectionId, 'Message body is required');
      return { statusCode: 400 };
    }

    const message: WebSocketMessage = JSON.parse(event.body);
    
    if (!message.action) {
      await websocketService.sendError(connectionId, 'Action is required', message.requestId);
      return { statusCode: 400 };
    }

    const connection = await connectionService.getConnection(connectionId);
    if (!connection) {
      await websocketService.sendError(connectionId, 'Connection not found', message.requestId);
      return { statusCode: 404 };
    }

    await handleAction(message, connection, connectionId);
    
    return { statusCode: 200 };
  } catch (error) {
    console.error('Error handling message:', error);
    
    try {
      const { connectionId } = event.requestContext;
      await websocketService.sendError(connectionId, 'Internal server error');
    } catch (sendError) {
      console.error('Error sending error message:', sendError);
    }
    
    return { statusCode: 500 };
  }
};

async function handleAction(
  message: WebSocketMessage, 
  connection: any, 
  connectionId: string
): Promise<void> {
  switch (message.action) {
    case WebSocketAction.JOIN_ROOM:
      await handleJoinRoom(message, connection, connectionId);
      break;
    
    case WebSocketAction.LEAVE_ROOM:
      await handleLeaveRoom(message, connection, connectionId);
      break;
    
    case WebSocketAction.SEND_MESSAGE:
      await handleSendMessage(message, connection, connectionId);
      break;
    
    case WebSocketAction.EDIT_MESSAGE:
      await handleEditMessage(message, connection, connectionId);      break;

    case WebSocketAction.DELETE_MESSAGE:
      await handleDeleteMessage(message, connection, connectionId);
      break;

    case WebSocketAction.LIST_ROOMS:
      await handleListRooms(message, connection, connectionId);
      break;

    case WebSocketAction.CREATE_ROOM:
      await handleCreateRoom(message, connection, connectionId);
      break;

    case WebSocketAction.GET_ROOM_HISTORY:
      await handleGetRoomHistory(message, connection, connectionId);
      break;

    case WebSocketAction.TYPING_START:
    case WebSocketAction.TYPING_STOP:
      await handleTypingIndicator(message, connection, connectionId);
      break;
    
    default:
      await websocketService.sendError(connectionId, `Unknown action: ${message.action}`, message.requestId);
  }
}

async function handleJoinRoom(
  message: WebSocketMessage, 
  connection: any, 
  connectionId: string
): Promise<void> {
  const { roomId } = message.data;
  
  if (!roomId) {
    await websocketService.sendError(connectionId, 'Room ID is required', message.requestId);
    return;
  }

  const room = await chatService.getRoom(roomId);
  if (!room) {
    await websocketService.sendError(connectionId, 'Room not found', message.requestId);
    return;
  }

  // Check if user has permission to join room
  if (room.isPrivate && !room.members.includes(connection.userId)) {
    await websocketService.sendError(connectionId, 'Access denied', message.requestId);
    return;
  }

  // Update connection with room info
  await connectionService.updateConnectionRoom(connectionId, roomId);

  // Notify room members that user joined
  await websocketService.broadcastToRoom({
    type: 'user_joined',
    data: {
      userId: connection.userId,
      username: connection.username,
      joinedAt: new Date().toISOString(),
    },
    roomId,
    excludeConnectionId: connectionId,
  });

  // Send success response with room info
  await websocketService.sendSuccess(connectionId, {
    room,
    message: 'Successfully joined room',
  }, message.requestId);
}

async function handleLeaveRoom(
  message: WebSocketMessage, 
  connection: any, 
  connectionId: string
): Promise<void> {
  if (!connection.roomId) {
    await websocketService.sendError(connectionId, 'Not currently in a room', message.requestId);
    return;
  }

  const roomId = connection.roomId;

  // Update connection to remove room
  await connectionService.updateConnectionRoom(connectionId, null);

  // Notify room members that user left
  await websocketService.broadcastToRoom({
    type: 'user_left',
    data: {
      userId: connection.userId,
      username: connection.username,
      leftAt: new Date().toISOString(),
    },
    roomId,
    excludeConnectionId: connectionId,
  });
  await websocketService.sendSuccess(connectionId, {
    message: 'Successfully left room',
  }, message.requestId);
}

async function handleSendMessage(
  message: WebSocketMessage, 
  connection: any, 
  connectionId: string
): Promise<void> {
  const { content, messageType = MessageType.TEXT, replyToMessageId } = message.data;
  
  if (!connection.roomId) {
    await websocketService.sendError(connectionId, 'Must be in a room to send messages', message.requestId);
    return;
  }

  if (!content || content.trim().length === 0) {
    await websocketService.sendError(connectionId, 'Message content is required', message.requestId);
    return;
  }

  const chatMessage = await chatService.sendMessage({
    roomId: connection.roomId,
    userId: connection.userId,
    username: connection.username,
    content: content.trim(),
    messageType,
    replyToMessageId,
  });

  // Broadcast message to all room members
  await websocketService.broadcastToRoom({
    type: 'message',
    data: chatMessage,
    roomId: connection.roomId,
  });

  await websocketService.sendSuccess(connectionId, {
    message: 'Message sent successfully',
    messageId: chatMessage.messageId,
  }, message.requestId);
}

async function handleEditMessage(
  message: WebSocketMessage, 
  connection: any, 
  connectionId: string
): Promise<void> {
  const { messageId, content } = message.data;
  
  if (!messageId || !content) {
    await websocketService.sendError(connectionId, 'Message ID and content are required', message.requestId);
    return;
  }

  const editedMessage = await chatService.editMessage(messageId, content.trim(), connection.userId);
  
  if (!editedMessage) {
    await websocketService.sendError(connectionId, 'Message not found or access denied', message.requestId);
    return;
  }

  // Broadcast updated message to room members
  await websocketService.broadcastToRoom({
    type: 'message',
    data: {
      ...editedMessage,
      edited: true,
    },
    roomId: editedMessage.roomId,
  });

  await websocketService.sendSuccess(connectionId, {
    message: 'Message edited successfully',
  }, message.requestId);
}

async function handleDeleteMessage(
  message: WebSocketMessage, 
  connection: any, 
  connectionId: string
): Promise<void> {
  const { messageId } = message.data;
  
  if (!messageId) {
    await websocketService.sendError(connectionId, 'Message ID is required', message.requestId);
    return;
  }

  const deleted = await chatService.deleteMessage(messageId, connection.userId);
  
  if (!deleted) {
    await websocketService.sendError(connectionId, 'Message not found or access denied', message.requestId);
    return;
  }

  // Broadcast deletion to room members
  if (connection.roomId) {
    await websocketService.broadcastToRoom({
      type: 'message',
      data: {
        messageId,
        deleted: true,
        deletedAt: new Date().toISOString(),
      },
      roomId: connection.roomId,
    });
  }

  await websocketService.sendSuccess(connectionId, {
    message: 'Message deleted successfully',
  }, message.requestId);
}

async function handleListRooms(
  message: WebSocketMessage, 
  connection: any, 
  connectionId: string
): Promise<void> {
  const { isPrivate, limit = 50 } = message.data || {};
  
  const rooms = await chatService.listRooms(isPrivate, limit);
  
  await websocketService.sendSuccess(connectionId, {
    rooms,
  }, message.requestId);
}

async function handleCreateRoom(
  message: WebSocketMessage, 
  connection: any, 
  connectionId: string
): Promise<void> {
  const { name, description, isPrivate = false, members = [] } = message.data;
  
  if (!name || name.trim().length === 0) {
    await websocketService.sendError(connectionId, 'Room name is required', message.requestId);
    return;
  }

  const room = await chatService.createRoom({
    name: name.trim(),
    description: description?.trim(),
    createdBy: connection.userId,
    isPrivate,
    members,
  });

  await websocketService.sendSuccess(connectionId, {
    room,
    message: 'Room created successfully',
  }, message.requestId);
}

async function handleGetRoomHistory(
  message: WebSocketMessage, 
  connection: any, 
  connectionId: string
): Promise<void> {
  const { roomId, limit = 50, exclusiveStartKey } = message.data;
  
  if (!roomId) {
    await websocketService.sendError(connectionId, 'Room ID is required', message.requestId);
    return;
  }

  const room = await chatService.getRoom(roomId);
  if (!room) {
    await websocketService.sendError(connectionId, 'Room not found', message.requestId);
    return;
  }

  // Check access permissions
  if (room.isPrivate && !room.members.includes(connection.userId)) {
    await websocketService.sendError(connectionId, 'Access denied', message.requestId);
    return;
  }

  const history = await chatService.getRoomHistory(roomId, limit, exclusiveStartKey);
  
  await websocketService.sendSuccess(connectionId, history, message.requestId);
}

async function handleTypingIndicator(
  message: WebSocketMessage, 
  connection: any, 
  connectionId: string
): Promise<void> {
  if (!connection.roomId) {
    return; // Silently ignore if not in a room
  }

  const isTyping = message.action === WebSocketAction.TYPING_START;

  await websocketService.broadcastToRoom({
    type: 'typing',
    data: {
      userId: connection.userId,
      username: connection.username,
      isTyping,
      timestamp: new Date().toISOString(),
    },
    roomId: connection.roomId,
    excludeConnectionId: connectionId,
  });
}
```

## SAM Template for WebSocket API

Create the infrastructure template:

```yaml
# template.yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Parameters:
  Stage:
    Type: String
    Default: dev
    Description: API Gateway deployment stage

Globals:
  Function:
    Timeout: 30
    Runtime: nodejs18.x
    Environment:
      Variables:
        TABLE_NAME: !Ref ChatTable
        STAGE: !Ref Stage

Resources:
  # WebSocket API
  ChatWebSocketApi:
    Type: AWS::ApiGatewayV2::Api
    Properties:
      Name: !Sub "chat-websocket-${Stage}"
      ProtocolType: WEBSOCKET
      RouteSelectionExpression: "$request.body.action"

  # WebSocket API Stage
  ChatWebSocketStage:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      ApiId: !Ref ChatWebSocketApi
      StageName: !Ref Stage
      AutoDeploy: true

  # DynamoDB Table
  ChatTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub "chat-table-${Stage}"
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
        - AttributeName: sk
          AttributeType: S
        - AttributeName: gsi1pk
          AttributeType: S
        - AttributeName: gsi1sk
          AttributeType: S
        - AttributeName: gsi2pk
          AttributeType: S
        - AttributeName: gsi2sk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
        - AttributeName: sk
          KeyType: RANGE
      GlobalSecondaryIndexes:
        - IndexName: GSI1
          KeySchema:
            - AttributeName: gsi1pk
              KeyType: HASH
            - AttributeName: gsi1sk
              KeyType: RANGE
          Projection:
            ProjectionType: ALL
        - IndexName: GSI2
          KeySchema:
            - AttributeName: gsi2pk
              KeyType: HASH
            - AttributeName: gsi2sk
              KeyType: RANGE
          Projection:
            ProjectionType: ALL
      TimeToLiveSpecification:
        AttributeName: ttl
        Enabled: true

  # Lambda Functions
  ConnectFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: dist/
      Handler: handlers/websocket/connect.handler
      Environment:
        Variables:
          API_ID: !Ref ChatWebSocketApi
          REGION: !Ref AWS::Region
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref ChatTable

  DisconnectFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: dist/
      Handler: handlers/websocket/disconnect.handler
      Environment:
        Variables:
          API_ID: !Ref ChatWebSocketApi
          REGION: !Ref AWS::Region
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref ChatTable
        - Statement:
            - Effect: Allow
              Action:
                - execute-api:ManageConnections
              Resource: !Sub "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${ChatWebSocketApi}/${Stage}/POST/@connections/*"

  MessageFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: dist/
      Handler: handlers/websocket/message.handler
      Environment:
        Variables:
          API_ID: !Ref ChatWebSocketApi
          REGION: !Ref AWS::Region
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref ChatTable
        - Statement:
            - Effect: Allow
              Action:
                - execute-api:ManageConnections
              Resource: !Sub "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${ChatWebSocketApi}/${Stage}/POST/@connections/*"

  # WebSocket Routes
  ConnectRoute:
    Type: AWS::ApiGatewayV2::Route
    Properties:
      ApiId: !Ref ChatWebSocketApi
      RouteKey: $connect
      AuthorizationType: NONE
      Target: !Join ['/', ['integrations', !Ref ConnectIntegration]]

  DisconnectRoute:
    Type: AWS::ApiGatewayV2::Route
    Properties:
      ApiId: !Ref ChatWebSocketApi
      RouteKey: $disconnect
      AuthorizationType: NONE
      Target: !Join ['/', ['integrations', !Ref DisconnectIntegration]]

  DefaultRoute:
    Type: AWS::ApiGatewayV2::Route
    Properties:
      ApiId: !Ref ChatWebSocketApi
      RouteKey: $default
      AuthorizationType: NONE
      Target: !Join ['/', ['integrations', !Ref MessageIntegration]]

  # Integrations
  ConnectIntegration:
    Type: AWS::ApiGatewayV2::Integration
    Properties:
      ApiId: !Ref ChatWebSocketApi
      IntegrationType: AWS_PROXY
      IntegrationUri: !Sub "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${ConnectFunction.Arn}/invocations"

  DisconnectIntegration:
    Type: AWS::ApiGatewayV2::Integration
    Properties:
      ApiId: !Ref ChatWebSocketApi
      IntegrationType: AWS_PROXY
      IntegrationUri: !Sub "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${DisconnectFunction.Arn}/invocations"

  MessageIntegration:
    Type: AWS::ApiGatewayV2::Integration
    Properties:
      ApiId: !Ref ChatWebSocketApi
      IntegrationType: AWS_PROXY
      IntegrationUri: !Sub "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${MessageFunction.Arn}/invocations"

  # Lambda Permissions
  ConnectPermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref ConnectFunction
      Principal: apigateway.amazonaws.com
      SourceArn: !Sub "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${ChatWebSocketApi}/*"

  DisconnectPermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref DisconnectFunction
      Principal: apigateway.amazonaws.com
      SourceArn: !Sub "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${ChatWebSocketApi}/*"

  MessagePermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref MessageFunction
      Principal: apigateway.amazonaws.com
      SourceArn: !Sub "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${ChatWebSocketApi}/*"

Outputs:
  WebSocketUrl:
    Description: "WebSocket API URL"
    Value: !Sub "wss://${ChatWebSocketApi}.execute-api.${AWS::Region}.amazonaws.com/${Stage}"
  
  TableName:
    Description: "DynamoDB table name"
    Value: !Ref ChatTable

  ApiId:
    Description: "WebSocket API ID"
    Value: !Ref ChatWebSocketApi
```

## Client-Side TypeScript Integration

Create a TypeScript client for WebSocket communication:

```typescript
// client/websocket-client.ts
export class ChatWebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private pingInterval: number | null = null;
  private messageHandlers = new Map<string, (data: any) => void>();
  private requestHandlers = new Map<string, { resolve: (data: any) => void; reject: (error: any) => void }>();

  constructor(url: string) {
    this.url = url;
  }

  connect(token?: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const wsUrl = token ? `${this.url}?authorization=${token}` : this.url;
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log('WebSocket connected');
        this.reconnectAttempts = 0;
        this.startPing();
        resolve();
      };

      this.ws.onmessage = (event) => {
        this.handleMessage(JSON.parse(event.data));
      };

      this.ws.onclose = (event) => {
        console.log('WebSocket disconnected:', event.code, event.reason);
        this.stopPing();
        
        if (!event.wasClean && this.reconnectAttempts < this.maxReconnectAttempts) {
          setTimeout(() => {
            this.reconnectAttempts++;
            this.connect(token);
          }, this.reconnectDelay * Math.pow(2, this.reconnectAttempts));
        }
      };

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        reject(error);
      };
    });
  }

  disconnect(): void {
    this.stopPing();
    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
      this.ws = null;
    }
  }

  sendMessage(action: string, data: any): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        reject(new Error('WebSocket not connected'));
        return;
      }

      const requestId = generateId();
      const message = {
        action,
        data,
        requestId,
      };

      this.requestHandlers.set(requestId, { resolve, reject });
      this.ws.send(JSON.stringify(message));

      // Timeout after 30 seconds
      setTimeout(() => {
        if (this.requestHandlers.has(requestId)) {
          this.requestHandlers.delete(requestId);
          reject(new Error('Request timeout'));
        }
      }, 30000);
    });
  }

  onMessage(type: string, handler: (data: any) => void): void {
    this.messageHandlers.set(type, handler);
  }

  offMessage(type: string): void {
    this.messageHandlers.delete(type);
  }

  // Convenience methods
  async joinRoom(roomId: string): Promise<any> {
    return this.sendMessage('joinRoom', { roomId });
  }

  async leaveRoom(): Promise<any> {
    return this.sendMessage('leaveRoom', {});
  }

  async sendChatMessage(content: string, replyToMessageId?: string): Promise<any> {
    return this.sendMessage('sendMessage', { content, replyToMessageId });
  }

  async editMessage(messageId: string, content: string): Promise<any> {
    return this.sendMessage('editMessage', { messageId, content });
  }

  async deleteMessage(messageId: string): Promise<any> {
    return this.sendMessage('deleteMessage', { messageId });
  }

  async createRoom(name: string, description?: string, isPrivate = false, members: string[] = []): Promise<any> {
    return this.sendMessage('createRoom', { name, description, isPrivate, members });
  }

  async listRooms(isPrivate?: boolean): Promise<any> {
    return this.sendMessage('listRooms', { isPrivate });
  }

  async getRoomHistory(roomId: string, limit = 50): Promise<any> {
    return this.sendMessage('getRoomHistory', { roomId, limit });
  }

  startTyping(): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ action: 'typingStart', data: {} }));
    }
  }

  stopTyping(): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ action: 'typingStop', data: {} }));
    }
  }

  private handleMessage(message: any): void {
    if (message.requestId && this.requestHandlers.has(message.requestId)) {
      const handler = this.requestHandlers.get(message.requestId)!;
      this.requestHandlers.delete(message.requestId);
      
      if (message.type === 'error') {
        handler.reject(new Error(message.error));
      } else {
        handler.resolve(message.data);
      }
      return;
    }

    // Handle broadcast messages
    const handler = this.messageHandlers.get(message.type);
    if (handler) {
      handler(message.data);
    }
  }

  private startPing(): void {
    this.pingInterval = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ action: 'ping', data: {} }));
      }
    }, 30000) as any;
  }

  private stopPing(): void {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }
}

function generateId(): string {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}
```

## Conclusion

Building real-time applications with AWS WebSockets and TypeScript creates powerful, scalable communication systems that can handle thousands of concurrent users. The serverless approach eliminates infrastructure management while providing automatic scaling and cost optimization through pay-per-use pricing.

The patterns demonstrated in this post—from connection management and message routing to room-based broadcasting and typing indicators—provide a solid foundation for building sophisticated real-time applications. The type-safe approach ensures reliability and maintainability as your application scales and evolves.

This concludes our comprehensive journey through AWS and TypeScript, covering Lambda functions, Step Functions, SNS/SQS messaging, API Gateway, DynamoDB, CDK infrastructure as code, and WebSocket real-time communication. Together, these technologies provide a complete toolkit for building modern, scalable serverless applications that are both powerful and maintainable.
