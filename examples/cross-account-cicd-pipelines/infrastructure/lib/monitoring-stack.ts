import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { ApplicationStack } from './application-stack';

export interface MonitoringStackProps extends cdk.StackProps {
  environment: string;
  applicationStack: ApplicationStack;
}

export class MonitoringStack extends cdk.Stack {
  public readonly alertTopic: sns.Topic;
  public readonly deploymentDashboard: cloudwatch.Dashboard;

  constructor(scope: Construct, id: string, props: MonitoringStackProps) {
    super(scope, id, props);

    // Create SNS topic for alerts
    this.alertTopic = new sns.Topic(this, 'DeploymentAlerts', {
      topicName: `cross-account-alerts-${props.environment}`,
      displayName: `Cross-Account Deployment Alerts - ${props.environment}`,
      fifo: false
    });

    // Add email subscription (replace with your email)
    this.alertTopic.addSubscription(
      new subscriptions.EmailSubscription('your-email@example.com')
    );

    // Create CloudWatch dashboard
    this.deploymentDashboard = new cloudwatch.Dashboard(this, 'DeploymentDashboard', {
      dashboardName: `cross-account-deployment-${props.environment}`,
      defaultInterval: cdk.Duration.hours(24)
    });

    // Add Lambda metrics
    const lambdaMetrics = this.createLambdaMetrics(props.applicationStack.sampleLambda.functionName);
    
    this.deploymentDashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Lambda Invocations',
        left: [lambdaMetrics.invocations],
        right: [lambdaMetrics.errors],
        width: 12,
        height: 6
      }),
      new cloudwatch.GraphWidget({
        title: 'Lambda Duration',
        left: [lambdaMetrics.duration],
        width: 12,
        height: 6
      })
    );

    // Add custom deployment metrics
    const deploymentMetrics = this.createDeploymentMetrics();
    
    this.deploymentDashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Deployment Success Rate',
        left: [deploymentMetrics.successRate],
        width: 12,
        height: 6
      }),
      new cloudwatch.GraphWidget({
        title: 'Deployment Duration',
        left: [deploymentMetrics.duration],
        width: 12,
        height: 6
      })
    );

    // Create alarms
    this.createAlarms(props.applicationStack.sampleLambda.functionName);

    // Outputs
    new cdk.CfnOutput(this, 'AlertTopicArn', {
      value: this.alertTopic.topicArn,
      description: `Alert topic ARN for ${props.environment} environment`,
      exportName: `AlertTopicArn-${props.environment}`
    });

    new cdk.CfnOutput(this, 'DashboardUrl', {
      value: `https://console.aws.amazon.com/cloudwatch/home?region=${cdk.Stack.of(this).region}#dashboards:name=${this.deploymentDashboard.dashboardName}`,
      description: `CloudWatch dashboard URL for ${props.environment} environment`,
      exportName: `DashboardUrl-${props.environment}`
    });
  }

  private createLambdaMetrics(functionName: string) {
    return {
      invocations: new cloudwatch.Metric({
        namespace: 'AWS/Lambda',
        metricName: 'Invocations',
        dimensionsMap: {
          FunctionName: functionName
        },
        statistic: 'Sum'
      }),
      errors: new cloudwatch.Metric({
        namespace: 'AWS/Lambda',
        metricName: 'Errors',
        dimensionsMap: {
          FunctionName: functionName
        },
        statistic: 'Sum'
      }),
      duration: new cloudwatch.Metric({
        namespace: 'AWS/Lambda',
        metricName: 'Duration',
        dimensionsMap: {
          FunctionName: functionName
        },
        statistic: 'Average'
      })
    };
  }

  private createDeploymentMetrics() {
    return {
      successRate: new cloudwatch.Metric({
        namespace: 'CrossAccount/Deployment',
        metricName: 'DeploymentSuccess',
        dimensionsMap: {
          Environment: this.node.tryGetContext('environment') || 'development'
        },
        statistic: 'Average'
      }),
      duration: new cloudwatch.Metric({
        namespace: 'CrossAccount/Deployment',
        metricName: 'DeploymentDuration',
        dimensionsMap: {
          Environment: this.node.tryGetContext('environment') || 'development'
        },
        statistic: 'Average'
      })
    };
  }

  private createAlarms(functionName: string) {
    // Lambda error rate alarm
    const lambdaErrorAlarm = new cloudwatch.Alarm(this, 'LambdaErrorAlarm', {
      alarmName: `${functionName}-errors`,
      alarmDescription: `High error rate for ${functionName}`,
      metric: new cloudwatch.Metric({
        namespace: 'AWS/Lambda',
        metricName: 'Errors',
        dimensionsMap: {
          FunctionName: functionName
        },
        statistic: 'Sum'
      }),
      threshold: 5,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD
    });

    lambdaErrorAlarm.addAlarmAction(
      new cdk.aws_cloudwatch_actions.SnsAction(this.alertTopic)
    );

    // Deployment failure alarm
    const deploymentFailureAlarm = new cloudwatch.Alarm(this, 'DeploymentFailureAlarm', {
      alarmName: `deployment-failures-${this.node.tryGetContext('environment')}`,
      alarmDescription: 'Deployment failure detected',
      metric: new cloudwatch.Metric({
        namespace: 'CrossAccount/Deployment',
        metricName: 'DeploymentSuccess',
        dimensionsMap: {
          Environment: this.node.tryGetContext('environment') || 'development'
        },
        statistic: 'Average'
      }),
      threshold: 0.8, // Alert if success rate drops below 80%
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
    });

    deploymentFailureAlarm.addAlarmAction(
      new cdk.aws_cloudwatch_actions.SnsAction(this.alertTopic)
    );
  }
}
