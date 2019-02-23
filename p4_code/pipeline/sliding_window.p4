// This file is included in flowselector.p4

// Variables used for the sliding window
bit<19> last_sw_time;
bit<4> cur_sw_index;
bit<6> cur_sw_sum;
bit<6> cur_sw_val;

bit<48> shift;

sw_time.read(last_sw_time, custom_metadata.id);

// If the sliding window is too late by 1s or more, re initialize it
if (custom_metadata.ingress_timestamp_millisecond - last_sw_time > SW_BINS_DURATION*(bit<19>)(SW_NB_BINS))
{
    sw_time.write(custom_metadata.id, custom_metadata.ingress_timestamp_millisecond);
    sw_index.write(custom_metadata.id, 0);
    sw_sum.write(custom_metadata.id, 0);
    sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+0, 0);
    sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+1, 0);
    sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+2, 0);
    sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+3, 0);
    sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+4, 0);
    sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+5, 0);
    sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+6, 0);
    sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+7, 0);
    sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+8, 0);
    sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+9, 0);
}

sw_time.read(last_sw_time, custom_metadata.id);
sw_index.read(cur_sw_index, custom_metadata.id);
sw_sum.read(cur_sw_sum, custom_metadata.id);


if (custom_metadata.ingress_timestamp_millisecond - last_sw_time > SW_BINS_DURATION)
{
    shift = 0;
    // Compute the shift (without division)
    // Basically same as     shift = (custom_metadata.ingress_timestamp_millisecond - last_sw_time)/SW_BINS_DURATION;
    if (custom_metadata.ingress_timestamp_millisecond - last_sw_time < SW_BINS_DURATION)
    {
        shift = 0;
    }
    else if (custom_metadata.ingress_timestamp_millisecond - last_sw_time < 2*SW_BINS_DURATION)
    {
        shift = 1;
    }
    else if (custom_metadata.ingress_timestamp_millisecond - last_sw_time < 3*SW_BINS_DURATION)
    {
        shift = 2;
    }
    else if (custom_metadata.ingress_timestamp_millisecond - last_sw_time < 4*SW_BINS_DURATION)
    {
        shift = 3;
    }
    else if (custom_metadata.ingress_timestamp_millisecond - last_sw_time < 5*SW_BINS_DURATION)
    {
        shift = 4;
    }
    else
    {
        shift = 5;
    }

    if (shift > 0)
    {
        // Increase the timestamp by a bin time
        last_sw_time = last_sw_time + SW_BINS_DURATION;
        // Move to the next index
        cur_sw_index = cur_sw_index + 4w1;
        if (cur_sw_index >= SW_NB_BINS)
        {
            cur_sw_index = 0;
        }

        // Read the value in the current bin of the Sliding window
        sw.read(cur_sw_val, (custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)cur_sw_index);
        // Remove from the global sum that value
        cur_sw_sum = cur_sw_sum - cur_sw_val;
        // Set 0 into the new bin
        sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)cur_sw_index, 0);

        // Decrease shift by one
        shift = shift - 1;
    }

    if (shift > 0)
    {
        last_sw_time = last_sw_time + SW_BINS_DURATION;
        cur_sw_index = cur_sw_index + 4w1;
        if (cur_sw_index >= SW_NB_BINS)
        {
            cur_sw_index = 0;
        }

        sw.read(cur_sw_val, (custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)cur_sw_index);
        cur_sw_sum = cur_sw_sum - cur_sw_val;
        sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)cur_sw_index, 0);

        shift = shift - 1;
    }
    if (shift > 0)
    {
        last_sw_time = last_sw_time + SW_BINS_DURATION;
        cur_sw_index = cur_sw_index + 4w1;
        if (cur_sw_index >= SW_NB_BINS)
        {
            cur_sw_index = 0;
        }

        sw.read(cur_sw_val, (custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)cur_sw_index);
        cur_sw_sum = cur_sw_sum - cur_sw_val;
        sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)cur_sw_index, 0);

        shift = shift - 1;
    }
    if (shift > 0)
    {
        last_sw_time = last_sw_time + SW_BINS_DURATION;
        cur_sw_index = cur_sw_index + 4w1;
        if (cur_sw_index >= SW_NB_BINS)
        {
            cur_sw_index = 0;
        }

        sw.read(cur_sw_val, (custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)cur_sw_index);
        cur_sw_sum = cur_sw_sum - cur_sw_val;
        sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)cur_sw_index, 0);

        shift = shift - 1;
    }
    if (shift > 0)
    {
        last_sw_time = last_sw_time + SW_BINS_DURATION;
        cur_sw_index = cur_sw_index + 4w1;
        if (cur_sw_index >= SW_NB_BINS)
        {
            cur_sw_index = 0;
        }

        sw.read(cur_sw_val, (custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)cur_sw_index);
        cur_sw_sum = cur_sw_sum - cur_sw_val;
        sw.write((custom_metadata.id*(bit<32>)SW_NB_BINS)+(bit<32>)cur_sw_index, 0);

        shift = shift - 1;
    }

    sw_time.write(custom_metadata.id, last_sw_time);
    sw_index.write(custom_metadata.id, cur_sw_index);
    sw_sum.write(custom_metadata.id, cur_sw_sum);
}
