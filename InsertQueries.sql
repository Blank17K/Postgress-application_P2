--Enter Evidence
INSERT INTO al.EvidenceCatalog (evidence_hash, file_type)--ASKED AI to generate SHA 256 codes
	VALUES
		('4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce','.log'),
		('2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3','.log'),
		('6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b','.log'),
		('d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35','.log');

--Network Incident
INSERT INTO al.NetworkIncident(incident_code, target_ip, severity, detected_at, slice_id, evidence_hashes)
	VALUES
		('af3af377b7', '192.172.1.100', 'HIGH', CURRENT_TIMESTAMP,'slicing_A', 
			ARRAY['4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce',
				'2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3'] ),
		('gf3bf377b7', '182.192.8.155', 'CRITICAL', CURRENT_TIMESTAMP,'slicing_B', 
			ARRAY['6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'] ),
		('hf6bz377b7', '172.152.0.199', 'LOW', CURRENT_TIMESTAMP,'slicing_C', 
			ARRAY['d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35'] );

--Node Breach Incident
-- Insert into NodeBreachIncident (at least 2 valid records)
INSERT INTO al.NodeBreachIncident (
	incident_code, target_ip, severity, detected_at, node_id, 
    	assigned_investigator, is_contained) 
	VALUES
		('incident_1', '182.178.2.200', 'HIGH', CURRENT_TIMESTAMP, 'NODE_42',
 			ROW('Mrs.', 'Alice', 'Jane')::al.InvestigatorName, FALSE),
		('incident_2', '107.18.1.155', 'CRITICAL', CURRENT_TIMESTAMP, 'NODE_17',
		 	ROW('Mr.', 'Kano', 'Tshwale')::al.InvestigatorName, FALSE);


--Search Report
SELECT 
    incident_code, target_ip, is_contained,
    	al.format_investigator_name(assigned_investigator) AS investigator_on_site
FROM al.NodeBreachIncident;

-- hash Lookup
SELECT * 
FROM al.NetworkIncident 
WHERE '4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce' = ANY(evidence_hashes);

--
SELECT 
    slice_id,
    COUNT(*) AS total_critical_high_incidents
FROM al.NetworkIncident
WHERE severity = 'CRITICAL' OR severity = 'HIGH'
GROUP BY slice_id
ORDER BY total_critical_high_incidents DESC;