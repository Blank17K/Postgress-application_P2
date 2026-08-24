create database Aegis_Digital_Forensics; --This creates the company database
create schema al; -- al => auditLog where all created items and tables will go.

--_______________Custom Types & Domains_________________

create DOMAIN al.NodeIPType AS VARCHAR(15) --IPV4 has a max of 15 chars in it
	CHECK(VALUE ~  '^([0-9]{1,3}\.){3}[0-9]{1,3}$'); -- AI Helped Gen REGREX

create TYPE al.ServerityType as ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

create TYPE al.InvestigatorName AS (--Template for investigator insertion.
	title VARCHAR(10),
	first_name VARCHAR(50),
	last_name VARCHAR(50)
);
-- _____________________SEQUENCES_________________________
create SEQUENCE al.incident_seq START 1; -- Primary KEY Generated id's by system
create SEQUENCE al.evidence_seq START 1;
--__________________________Tables__________________________

create TABLE al.Incident(--Parent Class
	incident_id INTEGER DEFAULT nextval('al.incident_seq') PRIMARY KEY,
	incident_code VARCHAR(10) UNIQUE,
	target_ip al.NodeIPType,
	severity al.ServerityType,
	detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

--_________CHILD CLASSES__________
create TABLE al.NetworkIncident(
	slice_id VARCHAR(20),
	evidence_hashes TEXT[]
) INHERITS (al.Incident);

create TABLE al.NodeBreachIncident(
	node_id VARCHAR(20),
	assigned_investigator al.InvestigatorName,
	is_contained BOOLEAN DEFAULT false
)INHERITS (al.Incident);

--_____________________Auxiliary Lookup & Audit Tables__________________

create TABLE al.EvidenceCatalog(
	hash_id INTEGER DEFAULT nextval('al.evidence_seq') PRIMARY KEY,
	evidence_hash TEXT UNIQUE,
	file_type VARCHAR(20)
);


-- ______For DELETE TABLE_______
create TYPE al.NI_NBI AS(
	incident_id INTEGER,
    incident_code VARCHAR(10),
    target_ip al.NodeIPType,
    severity al.ServerityType,
    detected_at TIMESTAMP,
    slice_id VARCHAR(20),
    evidence_hashes TEXT[],
    node_id VARCHAR(20),
    assigned_investigator al.InvestigatorName,
    is_contained BOOLEAN
);
create TABLE al.DeletedIncidentAudit(
	deleted_rec al.NI_NBI,--Make sure to use ROW()
	deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	deleted_by VARCHAR(50) NOT NULL
);



---_________________________________Functions_________________________________
--___View Investigator Details
create OR replace FUNCTION al.format_investigator_name(
	person al.InvestigatorName
) RETURNs TEXT AS $$
BEGIN
	return person.title || ' '|| person.first_name||' '||person.last_name;
END;
$$ LANGUAGE plpgsql;

--___Check for registred hash
create OR replace FUNCTION al.is_hash_registered(
	hash TEXT
)RETURNS BOOLEAN AS $$
DECLARE
	number_of_hashes INTEGER;
BEGIN
	SELECT COUNT(*) INTO number_of_hashes
	FROM al.EvidenceCatalog
	WHERE evidence_hash = hash;

	return number_of_hashes>0;
END;
$$ LANGUAGE plpgsql;


--__Check for Duplicate hashes
create OR replace FUNCTION al.has_duplicate_hashes(
	hashes TEXT[]
)RETURNS BOOLEAN AS $$
DECLARE
	duplicateCount INTEGER;
	itt1 TEXT;
	itt2 TEXT;
BEGIN
	duplicateCount:=0;
	FOREACH itt1 IN ARRAY hashes
	LOOP
		FOREACH itt2 IN ARRAY hashes
		LOOP
			IF itt1 = itt2 THEN
                duplicateCount := duplicateCount+1;
			END IF;
		END LOOP;
		IF duplicateCount>1 THEN
			RETURN TRUE;
		END IF;
		duplicateCount:=0;
	END LOOP;
	return FALSE;
END;
$$ LANGUAGE plpgsql;


--___ADD all validations to Evidence
create OR replace FUNCTION al.validate_evidence_array(
	hashes TEXT[]
)RETURNS BOOLEAN AS $$
DECLARE
	itt1 TEXT;
BEGIN
	--NULL CHECK ADVISED BY AI
	IF hashes IS NULL THEN
		return FALSE;
	END IF;

	--_CHECK if hash is registered
	FOREACH itt1 IN ARRAY hashes
	LOOP
		IF NOT al.is_hash_registered(itt1)THEN
			return FALSE;
		END IF;
	END LOOP;

	--Check for duplicates
	IF al.has_duplicate_hashes(hashes)THEN
		return FALSE;
	END IF;
	return TRUE;
END;
$$ LANGUAGE plpgsql;
	



--_________________________________________TRIGGERS______________________________
-- CHECK VALID EVIDENCE
create OR replace FUNCTION al.check_evidence_integrity()
RETURNS TRIGGER AS $$
BEGIN
	IF NOT al.validate_evidence_array(NEW.evidence_hashes) THEN
		RAISE EXCEPTION 'Evidence hashes Either is EMPTY, has not been Registred into Evidence or contains DUPLICATE values';
	END IF;
	return NEW;
END;
$$ LANGUAGE plpgsql;

create OR replace TRIGGER evidence_integrity
	BEFORE INSERT  OR UPDATE ON al.NetworkIncident
	FOR EACH ROW
	EXECUTE FUNCTION al.check_evidence_integrity();

--______AuditTrail____
create OR replace FUNCTION al.audit_deleted_incident()
RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO al.DeletedIncidentAudit (deleted_rec,deleted_at,deleted_by)
	VALUES(
		ROW(OLD.incident_id,OLD.incident_code,OLD.target_ip,OLD.severity,
			OLD.detected_at,
			NULL,NULL,NULL,NULL,NULL)::al.NI_NBI,
					CURRENT_TIMESTAMP, CURRENT_USER);
	return OLD;
END;
$$ LANGUAGE plpgsql;

--For al.NetworkIncident
create OR replace TRIGGER audit_deleted_network_incident
	AFTER DELETE ON al.NetworkIncident
	FOR EACH ROW
	EXECUTE FUNCTION al.audit_deleted_incident();

--For al.NodeBreachIncident
create OR replace TRIGGER audit_deleted_node_breach_incident
	AFTER DELETE ON al.NodeBreachIncident
	FOR EACH ROW
	EXECUTE FUNCTION al.audit_deleted_incident();











