import { CloudTrailClient, LookupEventsCommand } from '@aws-sdk/client-cloudtrail';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

export interface AuditEvent {
  timestamp: Date;
  user: string;
  action: string;
  resource: string;
  sourceAccount: string;
  targetAccount: string;
  result: 'SUCCESS' | 'FAILURE';
  details?: Record<string, any>;
}

export class DeploymentAuditor {
  private readonly cloudTrail: CloudTrailClient;
  private readonly sns: SNSClient;

  constructor(
    private readonly notificationTopicArn: string,
    region: string = 'us-east-1'
  ) {
    this.cloudTrail = new CloudTrailClient({ region });
    this.sns = new SNSClient({ region });
  }

  async logDeploymentEvent(event: AuditEvent): Promise<void> {
    console.log('Deployment audit event:', JSON.stringify(event, null, 2));

    // Send notification for high-risk events
    if (this.isHighRiskEvent(event)) {
      await this.sendSecurityNotification(event);
    }

    // Store in audit trail (implementation depends on your requirements)
    await this.storeAuditEvent(event);
  }

  async getRecentDeploymentEvents(
    startTime: Date,
    endTime: Date,
    targetAccount?: string
  ): Promise<AuditEvent[]> {
    const command = new LookupEventsCommand({
      StartTime: startTime,
      EndTime: endTime,
      LookupAttributes: [
        {
          AttributeKey: 'EventName',
          AttributeValue: 'AssumeRoleWithWebIdentity'
        }
      ]
    });

    const response = await this.cloudTrail.send(command);
    const events: AuditEvent[] = [];

    for (const event of response.Events || []) {
      if (this.isDeploymentEvent(event) && 
          (!targetAccount || event.Username?.includes(targetAccount))) {
        events.push({
          timestamp: event.EventTime || new Date(),
          user: event.Username || 'Unknown',
          action: event.EventName || 'Unknown',
          resource: event.Resources?.[0]?.ResourceName || 'Unknown',
          sourceAccount: event.CloudTrailEvent ? 
            JSON.parse(event.CloudTrailEvent).recipientAccountId : 'Unknown',
          targetAccount: this.extractTargetAccount(event),
          result: event.ErrorCode ? 'FAILURE' : 'SUCCESS',
          details: event.CloudTrailEvent ? JSON.parse(event.CloudTrailEvent) : undefined
        });
      }
    }

    return events;
  }

  private isHighRiskEvent(event: AuditEvent): boolean {
    // Define criteria for high-risk events
    return event.targetAccount.includes('prod') || 
           event.action.includes('Delete') ||
           event.result === 'FAILURE';
  }

  private async sendSecurityNotification(event: AuditEvent): Promise<void> {
    const message = {
      alert: 'High-Risk Deployment Event',
      timestamp: event.timestamp.toISOString(),
      user: event.user,
      action: event.action,
      targetAccount: event.targetAccount,
      result: event.result,
      details: event.details
    };

    const command = new PublishCommand({
      TopicArn: this.notificationTopicArn,
      Subject: `Security Alert: ${event.action} in ${event.targetAccount}`,
      Message: JSON.stringify(message, null, 2)
    });

    await this.sns.send(command);
  }

  private async storeAuditEvent(event: AuditEvent): Promise<void> {
    // Implementation depends on your audit storage requirements
    // Could be DynamoDB, S3, CloudWatch Logs, or external SIEM
    console.log('Storing audit event:', event);
  }

  private isDeploymentEvent(event: any): boolean {
    // Logic to identify deployment-related CloudTrail events
    return event.EventName === 'AssumeRoleWithWebIdentity' &&
           event.Username?.includes('GitHubActions');
  }

  private extractTargetAccount(event: any): string {
    // Extract target account from CloudTrail event
    if (event.CloudTrailEvent) {
      const parsedEvent = JSON.parse(event.CloudTrailEvent);
      return parsedEvent.recipientAccountId || 'Unknown';
    }
    return 'Unknown';
  }
}
