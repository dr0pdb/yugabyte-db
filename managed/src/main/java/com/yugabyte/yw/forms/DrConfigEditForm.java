// Copyright (c) Yugabyte, Inc.

package com.yugabyte.yw.forms;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.List;
import javax.validation.Valid;
import lombok.ToString;

@ApiModel(description = "drConfig edit form")
@ToString
public class DrConfigEditForm {
  @Valid
  @ApiModelProperty("Parameters used to do Backup/restore")
  public XClusterConfigRestartFormData.RestartBootstrapParams bootstrapParams;

  @Valid
  @ApiModelProperty("Parameters used to do PITR")
  public DrConfigCreateForm.PitrParams pitrParams;

  @Valid
  @ApiModelProperty("List of urls for webhook")
  public List<String> webhookUrls;
}
