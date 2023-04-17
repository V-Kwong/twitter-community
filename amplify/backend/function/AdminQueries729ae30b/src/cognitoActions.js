const {CognitoIdentityServiceProvider} = require('aws-sdk');

const cognitoIdentityServiceProvider = new CognitoIdentityServiceProvider();
const userPoolId = process.env.USERPOOL;

async function addUserToGroup(username, groupname) {
  const params = {
    GroupName: groupname,
    UserPoolId: userPoolId,
    Username: username,
  };

  console.log(`Attempting to add ${username} to ${groupname}`);

  try {
    const result = await cognitoIdentityServiceProvider
      .adminAddUserToGroup(params)
      .promise();
    console.log(`Success adding ${username} to ${groupname}`);
    return {
      message: `Success adding ${username} to ${groupname}`,
    };
  } catch (err) {
    console.log(err);
    throw err;
  }
}

async function removeUserFromGroup(username, groupname) {
  const params = {
    GroupName: groupname,
    UserPoolId: userPoolId,
    Username: username,
  };

  console.log(`Attempting to remove ${username} from ${groupname}`);

  try {
    const result = await cognitoIdentityServiceProvider
      .adminRemoveUserFromGroup(params)
      .promise();
    console.log(`Removed ${username} from ${groupname}`);
    return {
      message: `Removed ${username} from ${groupname}`,
    };
  } catch (err) {
    console.log(err);
    throw err;
  }
}

async function addAndJoinGroup(username, groupname) {
  const params = {
    GroupName: groupname,
    UserPoolId: userPoolId,
  };
  /**
   * Check if the group exists; if it doesn't, create it.
   */
  try {
    await cognitoIdentityServiceProvider.getGroup(params).promise();
  } catch (e) {
    await cognitoIdentityServiceProvider.createGroup(params).promise();
  }

  try {
    await addUserToGroup(username, groupname);
    return {
      message: `Success in creating ${groupname} and adding ${username}`,
    };
  } catch (err) {
    console.log(err);
    throw err;
  }
}

async function listGroups(Limit, PaginationToken) {
  const params = {
    UserPoolId: userPoolId,
    ...(Limit && {Limit}),
    ...(PaginationToken && {PaginationToken}),
  };

  console.log('Attempting to list groups');

  try {
    const result = await cognitoIdentityServiceProvider
      .listGroups(params)
      .promise();

    // Rename to NextToken for consistency with other Cognito APIs
    result.NextToken = result.PaginationToken;
    delete result.PaginationToken;

    return result;
  } catch (err) {
    console.log(err);
    throw err;
  }
}

async function listGroupsForUser(username, Limit, NextToken) {
  const params = {
    UserPoolId: userPoolId,
    Username: username,
    ...(Limit && {Limit}),
    ...(NextToken && {NextToken}),
  };

  console.log(`Attempting to list groups for ${username}`);

  try {
    const result = await cognitoIdentityServiceProvider
      .adminListGroupsForUser(params)
      .promise();
    /**
     * We are filtering out the results that seem to be innapropriate for client applications
     * to prevent any informaiton disclosure. Customers can modify if they have the need.
     */
    result.Groups.forEach(val => {
      delete val.UserPoolId,
        delete val.LastModifiedDate,
        delete val.CreationDate,
        delete val.Precedence,
        delete val.RoleArn;
    });

    return result;
  } catch (err) {
    console.log(err);
    throw err;
  }
}

async function listUsersInGroup(groupname, Limit, NextToken) {
  const params = {
    GroupName: groupname,
    UserPoolId: userPoolId,
    ...(Limit && {Limit}),
    ...(NextToken && {NextToken}),
  };

  console.log(`Attempting to list users in group ${groupname}`);

  try {
    const result = await cognitoIdentityServiceProvider
      .listUsersInGroup(params)
      .promise();
    return result;
  } catch (err) {
    console.log(err);
    throw err;
  }
}

module.exports = {
  addUserToGroup,
  removeUserFromGroup,
  addAndJoinGroup,
  listGroups,
  listGroupsForUser,
  listUsersInGroup,
};
