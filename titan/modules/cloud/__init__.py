"""Cloud-native probing (Track D).

Storage-bucket exposure detection: when the scan's own evidence (leaked URLs,
hardcoded keys, reflected bodies) references a cloud storage bucket, probe it
for PUBLIC LISTING — the objective test for \"anyone can list/read this
bucket's contents\". Findings feed the flow-typed chain analyzer (data_leak
+ url_fetch => Public Cloud Storage Exposure).
"""
