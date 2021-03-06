/*************************************************************************
 * Copyright 2009-2013 Eucalyptus Systems, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 *
 * Please contact Eucalyptus Systems, Inc., 6755 Hollister Ave., Goleta
 * CA 93117, USA or visit http://www.eucalyptus.com/licenses/ if you need
 * additional information or have any questions.
 ************************************************************************/

package com.eucalyptus.tests.awssdk;

import static com.eucalyptus.tests.awssdk.Eutester4j.*;

import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import com.amazonaws.services.autoscaling.AmazonAutoScaling;
import com.amazonaws.services.autoscaling.model.AutoScalingGroup;
import com.amazonaws.services.autoscaling.model.CreateAutoScalingGroupRequest;
import com.amazonaws.services.autoscaling.model.CreateLaunchConfigurationRequest;
import com.amazonaws.services.autoscaling.model.DeleteAutoScalingGroupRequest;
import com.amazonaws.services.autoscaling.model.DeleteLaunchConfigurationRequest;
import com.amazonaws.services.autoscaling.model.DescribeAutoScalingGroupsRequest;
import com.amazonaws.services.autoscaling.model.DescribeAutoScalingGroupsResult;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.model.TerminateInstancesRequest;

/**
 * This application tests the inclusion of instance data when describing groups
 * 
 * This is verification for the story:
 * 
 * https://eucalyptus.atlassian.net/browse/EUCA-5013
 */
public class TestAutoScalingDescribeGroupsInstances {
	@SuppressWarnings("unchecked")
	@Test
	public void AutoScalingDescribeGroupsInstancesTest() throws Exception {
        testInfo(this.getClass().getSimpleName());
		getCloudInfo();
		final AmazonAutoScaling as = getAutoScalingClient(ACCESS_KEY, SECRET_KEY, AS_ENDPOINT);
		final AmazonEC2 ec2 = getEc2Client(ACCESS_KEY, SECRET_KEY, EC2_ENDPOINT);
		final String imageId = findImage(ec2);
		final String availabilityZone = findAvalablityZone(ec2);
		final String namePrefix = eucaUUID() + "-";
		logger.info("Using resource prefix for test: " + namePrefix);

		// End discovery, start test
		final List<Runnable> cleanupTasks = new ArrayList<Runnable>();
		try {
			// Create launch configuration
			final String configName = namePrefix + "DescribeGroupsInstances";
			logger.info("Creating launch configuration: " + configName);
			as.createLaunchConfiguration(new CreateLaunchConfigurationRequest()
					.withLaunchConfigurationName(configName)
					.withImageId(imageId).withInstanceType(INSTANCE_TYPE));
			cleanupTasks.add(new Runnable() {
				@Override
				public void run() {
					logger.info("Deleting launch configuration: " + configName);
					as.deleteLaunchConfiguration(new DeleteLaunchConfigurationRequest()
							.withLaunchConfigurationName(configName));
				}
			});

			// Create scaling group
			final String groupName = namePrefix + "DescribeGroupsInstances";
			logger.info("Creating auto scaling group: " + groupName);
			as.createAutoScalingGroup(new CreateAutoScalingGroupRequest()
					.withAutoScalingGroupName(groupName)
					.withLaunchConfigurationName(configName).withMinSize(1)
					.withMaxSize(1).withAvailabilityZones(availabilityZone));
			cleanupTasks.add(new Runnable() {
				@Override
				public void run() {
					logger.info("Deleting group: " + groupName);
					as.deleteAutoScalingGroup(new DeleteAutoScalingGroupRequest()
							.withAutoScalingGroupName(groupName)
							.withForceDelete(true));
				}
			});
			cleanupTasks.add(new Runnable() {
				@Override
				public void run() {
					final List<String> instanceIds = (List<String>) getInstancesForGroup(ec2, groupName, null, true);
					logger.info("Terminating instances: " + instanceIds);
					ec2.terminateInstances(new TerminateInstancesRequest()
							.withInstanceIds(instanceIds));
				}
			});

			// Wait for instances to launch
			logger.info("Waiting for instance to launch");
			final long timeout = TimeUnit.MINUTES.toMillis(2);
			final String instanceId = (String) waitForInstances(ec2, timeout, 1, groupName,true).get(0);

			// Verify instances are included when describing the group
			logger.info("Describing group");
			final DescribeAutoScalingGroupsResult describeGroupsResult = as
					.describeAutoScalingGroups(new DescribeAutoScalingGroupsRequest()
							.withAutoScalingGroupNames(groupName));
			assertThat(describeGroupsResult.getAutoScalingGroups() != null,
					"Groups null");
			assertThat(describeGroupsResult.getAutoScalingGroups().size() == 1,
					"Unexpected group count: "
							+ describeGroupsResult.getAutoScalingGroups()
									.size());
			final AutoScalingGroup group = describeGroupsResult
					.getAutoScalingGroups().get(0);
			assertThat(group != null, "Group is null");
			assertThat(groupName.equals(group.getAutoScalingGroupName()),
					"Unexpected group name: " + group.getAutoScalingGroupName());
			assertThat(group.getInstances() != null, "Group instances are null");
			assertThat(group.getInstances().size() == 1,
					"Unexpected instance count for group: "
							+ group.getInstances().size());
			final com.amazonaws.services.autoscaling.model.Instance asInstance = group
					.getInstances().get(0);
			assertThat(asInstance != null, "Instance is null");
			logger.info("Verifying instance information: " + asInstance);
			assertThat(instanceId.equals(asInstance.getInstanceId()),
					"Unexpected instance id: " + asInstance.getInstanceId());
			assertThat(
					configName.equals(asInstance.getLaunchConfigurationName()),
					"Unexpected launch configuration name: "
							+ asInstance.getLaunchConfigurationName());
			assertThat(
					availabilityZone.equals(asInstance.getAvailabilityZone()),
					"Unexpected availability zone: "
							+ asInstance.getAvailabilityZone());
			assertThat("Healthy".equals(asInstance.getHealthStatus()),
					"Unexpected health status: " + asInstance.getHealthStatus());
			assertThat(
					"InService".equals(asInstance.getLifecycleState()),
					"Unexpected lifecycle state: "
							+ asInstance.getLifecycleState());

			logger.info("Test complete");
		} finally {
			// Attempt to clean up anything we created
			Collections.reverse(cleanupTasks);
			for (final Runnable cleanupTask : cleanupTasks) {
				try {
					cleanupTask.run();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}
}
