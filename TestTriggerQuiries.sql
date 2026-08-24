--_______TEST TRIGGERS_______
--TG1:
INSERT INTO al.NetworkIncident(incident_code, target_ip, severity, detected_at, slice_id, evidence_hashes)
	VALUES
		('af3gg377b7', '192.152.7.197', 'LOW', CURRENT_TIMESTAMP,'slicing_D', 
			ARRAY['unregistredHASH-256']
	);

--TG2: Duplicate values:
INSERT INTO al.NetworkIncident (
    incident_code, target_ip, severity, detected_at, slice_id, evidence_hashes) 
	VALUES 
	('bf3gk3o7b8', '192.168.1.2', 'CRITICAL', CURRENT_TIMESTAMP, 'slicing_E',
    	ARRAY['d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35',
        	'd4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35'] );

--TG3: DELETE NetworkIncident
DELETE
FROM al.NetworkIncident
WHERE incident_code = 'gf3bf377b7';

--ViewDelete
SELECT * 
FROM al.DeletedIncidentAudit
WHERE (deleted_rec).incident_code = 'gf3bf377b7';

--TG3: DELETE NodeBreachIncident
DELETE
FROM al.NodeBreachIncident
WHERE incident_code = 'incident_1';

--ViewDelete
SELECT * 
FROM al.DeletedIncidentAudit
WHERE (deleted_rec).incident_code = 'incident_1';

SELECT *
FROM al.DeletedIncidentAudit;
