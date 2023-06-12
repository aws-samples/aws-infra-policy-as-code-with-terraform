package aws.emr.m5

test_valid_emr_bootstrapping {
    result = deny with input as data.mock.valid_emr_bootstrapping
    count(result) == 0
}

test_invalid_emr_bootstrapping_path{
    result = deny with input as data.mock.invalid_emr_bootstrapping_path
    msg = {"AWS-EMR-M-5: EMR cluster 'aws_emr_cluster.cluster' must be hardened with bootstrap actions."}
    result == msg
}

test_invalid_emr_bootstrapping_name{
    result = deny with input as data.mock.invalid_emr_bootstrapping_name
    msg = {"AWS-EMR-M-5: EMR cluster 'aws_emr_cluster.cluster' must be hardened with bootstrap actions."}
    result == msg
}

test_default_bootstrapping{
    result = deny with input as data.mock.default_bootstrapping
    msg = {"AWS-EMR-M-5: EMR cluster 'aws_emr_cluster.cluster' must be hardened with bootstrap actions."}
    result == msg
}
