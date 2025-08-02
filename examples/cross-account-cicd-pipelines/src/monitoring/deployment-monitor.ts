import { CloudWatchClient, PutMetricDataCommand, GetMetricStatisticsCommand } from '@aws-sdk/client-cloudwatch';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

export interface DeploymentMetrics {
  environment: string;
  duration: number;
  success: boolean;
  failureReason?: string;
  deployedServices: string[];
}

export class DeploymentMonitor {
  private readonly cloudWatch: CloudWatchClient;
  private readonly sns: SNSClient;

  constructor(
    private readonly alertTopicArn: string,
    region: string = 'us-east-1'
  ) {
    this.cloudWatch = new CloudWatchClient({ region });
    this.sns = new SNSClient({ region });
  }

  async recordDeploymentMetrics(metrics: DeploymentMetrics): Promise<void> {
    const metricData = [
      {
        MetricName: 'DeploymentDuration',
        Dimensions: [
          { Name: 'Environment', Value: metrics.environment }
        ],
        Value: metrics.duration,
        Unit: 'Seconds',
        Timestamp: new Date()
      },
      {
        MetricName: 'DeploymentSuccess',
        Dimensions: [
          { Name: 'Environment', Value: metrics.environment }
        ],
        Value: metrics.success ? 1 : 0,
        Unit: 'Count',
        Timestamp: new Date()
      },
      {
        MetricName: 'DeployedServices',
        Dimensions: [
          { Name: 'Environment', Value: metrics.environment }
        ],
        Value: metrics.deployedServices.length,
        Unit: 'Count',
        Timestamp: new Date()
      }
    ];

    const command = new PutMetricDataCommand({
      Namespace: 'CrossAccount/Deployment',
      MetricData: metricData
    });

    await this.cloudWatch.send(command);

    // Send alert if deployment failed
    if (!metrics.success) {
      await this.sendFailureAlert(metrics);
    }
  }

  async getDeploymentSuccessRate(
    environment: string,
    hours: number = 24
  ): Promise<number> {
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - (hours * 60 * 60 * 1000));

    const command = new GetMetricStatisticsCommand({
      Namespace: 'CrossAccount/Deployment',
      MetricName: 'DeploymentSuccess',
      Dimensions: [
        { Name: 'Environment', Value: environment }
      ],
      StartTime: startTime,
      EndTime: endTime,
      Period: 3600, // 1 hour periods
      Statistics: ['Average']
    });

    const response = await this.cloudWatch.send(command);
    const datapoints = response.Datapoints || [];

    if (datapoints.length === 0) {
      return 1.0; // No deployments = 100% success rate
    }

    const totalSuccessRate = datapoints.reduce((sum, dp) => sum + (dp.Average || 0), 0);
    return totalSuccessRate / datapoints.length;
  }

  private async sendFailureAlert(metrics: DeploymentMetrics): Promise<void> {
    const message = {
      alert: 'Deployment Failure',
      environment: metrics.environment,
      duration: metrics.duration,
      failureReason: metrics.failureReason,
      deployedServices: metrics.deployedServices,
      timestamp: new Date().toISOString()
    };

    const command = new PublishCommand({
      TopicArn: this.alertTopicArn,
      Subject: `Deployment Failed: ${metrics.environment}`,
      Message: JSON.stringify(message, null, 2)
    });

    await this.sns.send(command);
  }
}
