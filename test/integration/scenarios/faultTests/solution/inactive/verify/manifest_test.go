/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT license.
 * SPDX-License-Identifier: MIT
 */

package verify

import (
	"testing"
)

// 1. Deploy instance as inactive. Verify that the instance is inactive and deployment is not created.
// 2. Change instance as active. inject failpoint to postpone the deployment.
// 3. Change instance as inactive. Verify that the deployment is cleaned up.
func TestInstance_InActive(t *testing.T) {

}
