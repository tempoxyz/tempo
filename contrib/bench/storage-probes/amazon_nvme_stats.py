"""Read-only fallback for EC2 instance-store statistics on older nvme-cli.
Layout: linux-nvme/nvme-cli plugins/amzn/amzn-nvme.c, log page 0xD0.
Only instance-store namespaces identified by sysfs are queried by caller.
"""
import struct,subprocess

def decode(data):
    if len(data)<4096:raise ValueError('short NVMe statistics page')
    magic,version=struct.unpack_from('<II',data)
    if magic!=0xEC2C0D7E:raise ValueError('not an EC2 instance-store statistics page')
    names=['total_read_ops','total_write_ops','total_read_bytes','total_write_bytes',
           'total_read_time_us','total_write_time_us','reserved_ebs_iops_us','reserved_ebs_tp_us',
           'instance_store_volume_performance_exceeded_iops_us',
           'instance_store_volume_performance_exceeded_tp_us','volume_queue_length']
    result=dict(zip(names,struct.unpack_from('<11Q',data,8)))
    result.update(magic=hex(magic),version=version,collector='nvme_get_log_0xd0')
    for name,offset in [('read_histogram',512),('write_histogram',2056)]:
        count=struct.unpack_from('<Q',data,offset)[0]
        if count>64:raise ValueError('invalid histogram bin count')
        result[name]=[]
        for i in range(count):
            lo,hi,n,_=struct.unpack_from('<QQII',data,offset+8+24*i)
            result[name].append({'lower_us':lo,'upper_us':hi,'count':n})
    return result

def collect(node):
    argv=['nvme','get-log',node,'--log-id=0xd0','--log-len=4096','--raw-binary']
    try:
        p=subprocess.run(argv,capture_output=True,timeout=15)
        if p.returncode:return {'argv':argv,'error':p.stderr.decode(errors='replace'),'returncode':p.returncode}
        return {'argv':argv,'statistics':decode(p.stdout)}
    except (OSError,subprocess.TimeoutExpired,ValueError) as e:return {'argv':argv,'error':str(e)}
